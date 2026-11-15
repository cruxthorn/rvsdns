//! rvsdns — reverse DNS lookup, input via STDIN only.
//! Pipeline: STDIN -> parse -> adaptive resolve -> STDOUT. Bench -> STDERR.

use std::{
    collections::HashMap,
    io::{self, BufWriter, IsTerminal, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU16, AtomicU64, AtomicUsize, Ordering::Relaxed},
    },
    time::{Duration, Instant},
};

use futures::{Stream, StreamExt, stream};
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query, ResponseCode},
    rr::{Name, RData, RecordType},
};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    net::UdpSocket,
    sync::{Semaphore, SemaphorePermit, oneshot},
};

const MIN_CON: usize = 32;
const START_CON: usize = 64;
const MAX_CON: usize = 256;
const MAX_TRIES: usize = 2; // 1 attempt + 1 retry on another server

const BOOT_TIMEOUT: Duration = Duration::from_millis(500);
const MIN_TIMEOUT: Duration = Duration::from_millis(300);
const MAX_TIMEOUT: Duration = Duration::from_millis(1200);

const SOCKETS_PER_SERVER: usize = 4;
const RECV_BUF: usize = 4096;

const USAGE: &str = "rvsdns - fast reverse DNS lookup (Direct STDIN only)\n";
const RESOLVERS: [IpAddr; 10] = [
    // Cloudflare
    IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
    // Google
    IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
    // Quad9
    IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
    // OpenDNS
    IpAddr::V4(Ipv4Addr::new(208, 67, 222, 222)),
    // AdGuard
    IpAddr::V4(Ipv4Addr::new(94, 140, 14, 14)),
    // CleanBrowsing
    IpAddr::V4(Ipv4Addr::new(185, 228, 168, 9)),
    // Control D
    IpAddr::V4(Ipv4Addr::new(76, 76, 2, 0)),
    // Verisign
    IpAddr::V4(Ipv4Addr::new(64, 6, 64, 6)),
    // DNS.WATCH
    IpAddr::V4(Ipv4Addr::new(84, 200, 69, 80)),
    // DNS4EU
    IpAddr::V4(Ipv4Addr::new(86, 54, 11, 1)),
];

// ───────────────────────── input ─────────────────────────

/// Streaming STDIN, blank/invalid lines dropped.
fn ips() -> impl Stream<Item = IpAddr> {
    let lines = BufReader::new(tokio::io::stdin()).lines();
    stream::unfold(lines, |mut l| async move {
        let s = l.next_line().await.ok()??;
        Some((s, l))
    })
    .filter_map(|line| std::future::ready(line.trim().parse::<IpAddr>().ok()))
}


// ─────────────────── adaptive concurrency (AIMD) ───────────────────

struct Limiter {
    sem: Semaphore,
    /// High 32 bits: target concurrency. Low 32 bits: successes since the last increase.
    /// Keeping both in one word makes the read-modify-write below a single atomic step.
    state: AtomicU64,
    live: AtomicUsize, // permits that currently exist
    con_sum: AtomicU64,
    con_n: AtomicU64,
}

impl Limiter {
    fn new() -> Self {
        Self {
            sem: Semaphore::new(START_CON),
            state: ((START_CON as u64) << 32).into(),
            live: START_CON.into(),
            con_sum: 0.into(),
            con_n: 0.into(),
        }
    }

    fn limit(&self) -> usize {
        (self.state.load(Relaxed) >> 32) as usize
    }

    /// Returns the permit and the limit observed at start.
    async fn acquire(&self) -> (SemaphorePermit<'_>, usize) {
        let p = self.sem.acquire().await.expect("semaphore never closed");
        let in_flight = self.live.load(Relaxed).saturating_sub(self.sem.available_permits());
        self.con_sum.fetch_add(in_flight as u64, Relaxed);
        self.con_n.fetch_add(1, Relaxed);
        (p, self.limit())
    }

    /// Release; surplus permits (after a shrink) are forgotten instead of returned.
    fn release(&self, p: SemaphorePermit<'_>) {
        let mut live = self.live.load(Relaxed);
        loop {
            // Several tasks can release at once after a shrink. Only drop a permit while
            // `live` is still above the current limit, otherwise we would undershoot it.
            if live <= self.limit() {
                return;
            }
            match self
                .live
                .compare_exchange_weak(live, live - 1, Relaxed, Relaxed)
            {
                Ok(_) => {
                    p.forget();
                    return;
                }
                Err(actual) => live = actual,
            }
        }
    }

    /// Additive increase: +1 per `limit` successes.
    fn on_success(&self) {
        let mut st = self.state.load(Relaxed);
        loop {
            let limit = (st >> 32) as usize;
            if limit >= MAX_CON {
                return;
            }
            let streak = st as u32 as usize + 1;
            let grow = streak >= limit;
            let next = if grow {
                (limit as u64 + 1) << 32
            } else {
                ((limit as u64) << 32) | streak as u64
            };
            match self.state.compare_exchange_weak(st, next, Relaxed, Relaxed) {
                Ok(_) => {
                    if grow {
                        self.live.fetch_add(1, Relaxed);
                        self.sem.add_permits(1);
                    }
                    return;
                }
                Err(actual) => st = actual,
            }
        }
    }

    /// Multiplicative decrease on any loss signal, once per congestion event.
    fn on_backoff(&self, seen: usize) {
        let next = (seen * 7 / 8).max(MIN_CON);
        if next >= seen {
            return;
        }
        let mut st = self.state.load(Relaxed);
        loop {
            if (st >> 32) as usize != seen {
                return; // another task already reacted to this congestion window
            }
            match self
                .state
                .compare_exchange_weak(st, (next as u64) << 32, Relaxed, Relaxed)
            {
                Ok(_) => return,
                Err(actual) => st = actual,
            }
        }
    }

    fn avg_con(&self) -> u64 {
        self.con_sum.load(Relaxed) / self.con_n.load(Relaxed).max(1)
    }
}

// ─────────────────── latency, timeout, stats ───────────────────

#[derive(Default)]
struct Meter {
    /// High 32 bits: smoothed RTT in microseconds. Low 32 bits: RTT variance.
    rtt: AtomicU64,
    sum_us: AtomicU64,
    n: AtomicU64,
    tmo: AtomicU64,
    err: AtomicU64,
}

impl Meter {
    fn record(&self, d: Duration) {
        let us = u64::try_from(d.as_micros())
            .unwrap_or(u64::MAX)
            .clamp(1, u32::MAX as u64);
        self.sum_us.fetch_add(us, Relaxed);
        self.n.fetch_add(1, Relaxed);

        // SRTT and RTTVAR are one value: update both in a single CAS so that
        // concurrent replies cannot mix values from different samples.
        let mut st = self.rtt.load(Relaxed);
        loop {
            let s = st >> 32;
            let v = st & 0xffff_ffff;
            let next = if s == 0 {
                (us << 32) | (us / 2)
            } else {
                let delta = s.abs_diff(us);
                let v = ((v * 3 + delta) / 4).min(u32::MAX as u64);
                let s = ((s * 7 + us) / 8).min(u32::MAX as u64);
                (s << 32) | v
            };
            match self.rtt.compare_exchange_weak(st, next, Relaxed, Relaxed) {
                Ok(_) => return,
                Err(actual) => st = actual,
            }
        }
    }

    fn timeout(&self) -> Duration {
        let st = self.rtt.load(Relaxed);
        let s = st >> 32;
        if s == 0 {
            return BOOT_TIMEOUT;
        }
        let v = st & 0xffff_ffff;
        Duration::from_micros(s + 4 * v).clamp(MIN_TIMEOUT, MAX_TIMEOUT)
    }

    fn avg_ms(&self) -> f64 {
        self.sum_us.load(Relaxed) as f64 / self.n.load(Relaxed).max(1) as f64 / 1000.0
    }

    fn fail(&self, cause: Cause) {
        match cause {
            Cause::Timeout => self.tmo.fetch_add(1, Relaxed),
            Cause::Server => self.err.fetch_add(1, Relaxed),
        };
    }
}

// ─────────────────────── resolver ───────────────────────

#[derive(Clone, Copy)]
enum Cause {
    Timeout, // our deadline or the resolver's own
    Server,  // SERVFAIL, REFUSED, busy, I/O, protocol...
}

fn ptr_names(msg: &Message) -> Vec<String> {
    msg.answers
        .iter()
        .filter_map(|rec| match &rec.data {
            RData::PTR(p) => Some(p.0.to_utf8().trim_end_matches('.').to_owned()),
            _ => None,
        })
        .collect()
}

fn reply_from(msg: Message) -> Result<Vec<String>, Cause> {
    if msg.metadata.truncation {
        return Err(Cause::Server); // let the retry use another server
    }
    match msg.metadata.response_code {
        ResponseCode::NoError => Ok(ptr_names(&msg)),
        ResponseCode::NXDomain => Ok(Vec::new()),
        _ => Err(Cause::Server),
    }
}

const _: () = assert!(RESOLVERS.len() <= 64); // `tried` is a u64 bitmask

/// One request waiting for its reply on a shared socket.
struct Pending {
    query: Name,
    generation: u64,
    tx: oneshot::Sender<Message>,
}

impl Pending {
    fn matches(&self, msg: &Message) -> bool {
        msg.queries.len() == 1
            && msg.queries[0].name == self.query
            && msg.queries[0].query_type() == RecordType::PTR
    }
}

/// A UDP socket shared by every query sent to one nameserver address.
///
/// hickory 0.26 opens a fresh socket for every request, which means a fresh
/// source port and NAT flow for every lookup and every internal retry. At a few
/// hundred queries per second that exhausts the NAT table and replies are lost.
/// Here each socket owns the map of in-flight IDs: one recv loop demultiplexes
/// every reply, so a small fixed set of flows carries the whole run.
struct Channel {
    sock: Arc<UdpSocket>,
    server: SocketAddr,
    pending: Mutex<HashMap<u16, Pending>>,
    next_id: AtomicU16,
    next_generation: AtomicU64,
    inflight: AtomicUsize,
}

impl Channel {
    async fn new(server: SocketAddr) -> Self {
        let bind = match server {
            SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
        };
        let sock = Arc::new(UdpSocket::bind(bind).await.expect("cannot bind UDP socket"));
        Self {
            sock,
            server,
            pending: Mutex::new(HashMap::new()),
            next_id: 0.into(),
            next_generation: 0.into(),
            inflight: 0.into(),
        }
    }

    async fn query(&self, ip: IpAddr) -> Result<Vec<String>, Cause> {
        let name = Name::from(ip);
        let Some((id, generation, rx)) = self.register(name.clone()) else {
            return Err(Cause::Server);
        };
        let _guard = PendingGuard {
            chan: self,
            id,
            generation,
        };

        let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
        msg.metadata.recursion_desired = true;
        msg.add_query(Query::query(name, RecordType::PTR));
        let bytes = msg.to_vec().map_err(|_| Cause::Server)?;

        self.sock
            .send_to(&bytes, self.server)
            .await
            .map_err(|_| Cause::Server)?;

        let reply = rx.await.map_err(|_| Cause::Server)?;
        reply_from(reply)
    }

    fn register(&self, query: Name) -> Option<(u16, u64, oneshot::Receiver<Message>)> {
        let (tx, rx) = oneshot::channel();
        let generation = self.next_generation.fetch_add(1, Relaxed);
        let mut pending = self.pending.lock().expect("pending map poisoned");
        for _ in 0..=u16::MAX {
            let id = self.next_id.fetch_add(1, Relaxed);
            if let std::collections::hash_map::Entry::Vacant(e) = pending.entry(id) {
                e.insert(Pending {
                    query,
                    generation,
                    tx,
                });
                return Some((id, generation, rx));
            }
        }
        None
    }

    fn forget(&self, id: u16, generation: u64) {
        let Ok(mut pending) = self.pending.lock() else {
            return;
        };
        if pending.get(&id).is_some_and(|p| p.generation == generation) {
            pending.remove(&id);
        }
    }
}

/// Removes a pending entry when the request is cancelled or times out.
struct PendingGuard<'a> {
    chan: &'a Channel,
    id: u16,
    generation: u64,
}

impl Drop for PendingGuard<'_> {
    fn drop(&mut self) {
        self.chan.forget(self.id, self.generation);
    }
}

async fn recv_loop(chan: Arc<Channel>) {
    let mut buf = vec![0u8; RECV_BUF];
    loop {
        let Ok((len, src)) = chan.sock.recv_from(&mut buf).await else {
            continue;
        };
        if src.ip() != chan.server.ip() || src.port() != chan.server.port() {
            continue;
        }
        let Ok(msg) = Message::from_vec(&buf[..len]) else {
            continue;
        };
        if msg.metadata.message_type != MessageType::Response {
            continue;
        }

        let mut pending = chan.pending.lock().expect("pending map poisoned");
        let matches = pending
            .get(&msg.metadata.id)
            .is_some_and(|p| p.matches(&msg));
        if !matches {
            continue;
        }
        let p = pending.remove(&msg.metadata.id).expect("checked above");
        drop(pending);
        let _ = p.tx.send(msg);
    }
}

/// One server = one meter (own adaptive timeout) + a few shared sockets.
struct Server {
    ip: IpAddr,
    channels: Vec<Arc<Channel>>,
    meter: Meter,
    inflight: AtomicUsize,
}

impl Server {
    async fn new(ip: IpAddr) -> Self {
        let addr = SocketAddr::new(ip, 53);
        let mut channels = Vec::with_capacity(SOCKETS_PER_SERVER);
        for _ in 0..SOCKETS_PER_SERVER {
            let chan = Arc::new(Channel::new(addr).await);
            tokio::spawn(recv_loop(Arc::clone(&chan)));
            channels.push(chan);
        }
        Self {
            ip,
            channels,
            meter: Meter::default(),
            inflight: 0.into(),
        }
    }

    async fn query(&self, ip: IpAddr) -> Result<Vec<String>, Cause> {
        let Some(chan) = self
            .channels
            .iter()
            .min_by_key(|c| c.inflight.load(Relaxed))
        else {
            return Err(Cause::Server);
        };
        let _slot = Slot(&chan.inflight);
        chan.query(ip).await
    }
}

/// An attempt in flight on a server; released on drop, also on cancellation.
struct Slot<'a>(&'a AtomicUsize);

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Relaxed);
    }
}

struct Pool {
    servers: Vec<Server>,
    rr: AtomicUsize, // rotates tie-breaks
}

impl Pool {
    async fn new() -> Self {
        let mut servers = Vec::with_capacity(RESOLVERS.len());
        for &ip in &RESOLVERS {
            servers.push(Server::new(ip).await);
        }
        Self {
            servers,
            rr: 0.into(),
        }
    }

    /// Least-loaded server not in `tried`; marks the attempt as in flight.
    fn pick(&self, tried: u64) -> Option<(usize, &Server, Slot<'_>)> {
        let n = self.servers.len();
        let off = self.rr.fetch_add(1, Relaxed);
        let mut best: Option<(usize, &Server)> = None;
        for i in 0..n {
            let idx = (off + i) % n;
            if (tried >> idx) & 1 == 1 {
                continue;
            }
            let s = &self.servers[idx];
            if best.is_none_or(|(_, b)| s.inflight.load(Relaxed) < b.inflight.load(Relaxed)) {
                best = Some((idx, s));
            }
        }
        best.map(|(i, s)| {
            s.inflight.fetch_add(1, Relaxed);
            (i, s, Slot(&s.inflight))
        })
    }

    fn sum(&self, f: impl Fn(&Meter) -> u64) -> u64 {
        self.servers.iter().map(|s| f(&s.meter)).sum()
    }

    fn avg_ms(&self) -> f64 {
        let us = self.sum(|m| m.sum_us.load(Relaxed));
        let n = self.sum(|m| m.n.load(Relaxed));
        us as f64 / n.max(1) as f64 / 1000.0
    }
}

/// `None` = gave up after MAX_TRIES (distinct from a valid "no PTR" reply).
async fn lookup(pool: &Pool, lim: &Limiter, ip: IpAddr) -> (IpAddr, Option<Vec<String>>) {
    let (permit, seen) = lim.acquire().await;
    let (mut tried, mut result) = (0u64, None);
    for _ in 0..MAX_TRIES {
        let Some((i, s, _slot)) = pool.pick(tried) else { break };
        tried |= 1u64 << i;

        let t0 = Instant::now();
        let attempt = match tokio::time::timeout(s.meter.timeout(), s.query(ip)).await {
            Ok(res) => res,
            Err(_) => Err(Cause::Timeout),
        };
        match attempt {
            Ok(names) => {
                s.meter.record(t0.elapsed());
                lim.on_success();
                result = Some(names);
                break;
            }
            Err(cause) => {
                s.meter.fail(cause);
                lim.on_backoff(seen);
            }
        }
    }
    lim.release(permit);
    (ip, result)
}

fn emit(w: &mut impl Write, ip: IpAddr, names: &[String]) -> io::Result<()> {
    names.iter().try_for_each(|n| writeln!(w, "{ip}    {n}"))
}

// ─────────────────────── main ───────────────────────

#[tokio::main]
async fn main() {
    if io::stdin().is_terminal() {
        eprint!("{USAGE}");
        std::process::exit(2);
    }

    let pool = Pool::new().await;
    let lim = Limiter::new();
    let started = Instant::now();
    let (mut inp, mut out, mut fail) = (0u64, 0u64, 0u64);

    let mut w = BufWriter::new(io::stdout().lock());
    let mut results = pin!(
        ips()
            .map(|ip| lookup(&pool, &lim, ip))
            .buffer_unordered(MAX_CON)
    );

    while let Some((ip, res)) = results.next().await {
        inp += 1;
        let Some(names) = res else {
            fail += 1;
            continue;
        };
        out += u64::from(!names.is_empty());
        if emit(&mut w, ip, &names).is_err() {
            break; // e.g. broken pipe (| head)
        }
    }
    if inp == 0 {
        eprint!("{USAGE}");
        std::process::exit(2);
    }
    let _ = w.flush();

    eprintln!(
        "\nInp: {inp} | Out: {out} | Fail: {fail} | Time: {:.3}s | Lat: {:.3}ms | Con: {} | Tmo: {} | Err: {}",
        started.elapsed().as_secs_f64(),
        pool.avg_ms(),
        lim.avg_con(),
        pool.sum(|m| m.tmo.load(Relaxed)),
        pool.sum(|m| m.err.load(Relaxed)),
    );
    for s in &pool.servers {
        let m = &s.meter;
        let (ok, tmo, err) = (m.n.load(Relaxed), m.tmo.load(Relaxed), m.err.load(Relaxed));
        eprintln!(
            "  {:<15} Req: {} | Tmo: {tmo} | Err: {err} | Lat: {:.3}ms",
            s.ip.to_string(),
            ok + tmo + err,
            m.avg_ms(),
        );
    }
}
