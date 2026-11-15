//! rvsdns — reverse DNS lookup, input via STDIN only.
//! Pipeline: STDIN -> parse -> adaptive resolve -> STDOUT. Bench -> STDERR.

use std::{
    io::{self, BufWriter, IsTerminal, Write},
    net::{IpAddr, Ipv4Addr},
    pin::pin,
    sync::atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed},
    time::{Duration, Instant},
};

use futures::{Stream, StreamExt, stream};
use hickory_net::{NetError, runtime::TokioRuntimeProvider};
use hickory_proto::rr::RData;
use hickory_resolver::{
    Resolver, TokioResolver,
    config::{NameServerConfig, ResolverConfig},
    lookup::Lookup,
};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    sync::{Semaphore, SemaphorePermit},
};

const MIN_CON: usize = 32;
const START_CON: usize = 64;
const MAX_CON: usize = 256;
const MAX_TRIES: usize = 2; // 1 attempt + 1 retry on another server

const BOOT_TIMEOUT: Duration = Duration::from_millis(500);
const MIN_TIMEOUT: Duration = Duration::from_millis(300);
const MAX_TIMEOUT: Duration = Duration::from_millis(1200);

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
    srtt_us: AtomicU64,
    rttvar_us: AtomicU64,
    sum_us: AtomicU64,
    n: AtomicU64,
    tmo: AtomicU64,
    err: AtomicU64,
}

impl Meter {
    fn record(&self, d: Duration) {
        let us = d.as_micros() as u64;
        self.sum_us.fetch_add(us, Relaxed);
        self.n.fetch_add(1, Relaxed);
        let s = self.srtt_us.load(Relaxed);
        if s == 0 {
            self.srtt_us.store(us, Relaxed);
            self.rttvar_us.store(us / 2, Relaxed);
        } else {
            let v = self.rttvar_us.load(Relaxed);
            self.rttvar_us.store((v * 3 + s.abs_diff(us)) / 4, Relaxed);
            self.srtt_us.store((s * 7 + us) / 8, Relaxed);
        }
    }

    fn timeout(&self) -> Duration {
        match self.srtt_us.load(Relaxed) {
            0 => BOOT_TIMEOUT,
            s => Duration::from_micros(s + 4 * self.rttvar_us.load(Relaxed))
                .clamp(MIN_TIMEOUT, MAX_TIMEOUT),
        }
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


/// What one attempt told us.
enum Attempt {
    /// Valid reply, final. Empty = NXDOMAIN/NODATA.
    Reply(Vec<String>),
    /// No usable reply; back off and try again.
    Retry(Cause),
}

#[derive(Clone, Copy)]
enum Cause {
    Timeout, // our deadline or the resolver's own
    Server,  // SERVFAIL, REFUSED, busy, I/O, protocol...
}

fn ptr_names(l: &Lookup) -> Vec<String> {
    l.answers()
        .iter()
        .filter_map(|rec| match &rec.data {
            RData::PTR(p) => Some(p.0.to_utf8().trim_end_matches('.').to_owned()),
            _ => None,
        })
        .collect()
}

fn classify(res: Result<Lookup, NetError>) -> Attempt {
    match res {
        Ok(l) => Attempt::Reply(ptr_names(&l)),
        Err(e) if e.is_no_records_found() => Attempt::Reply(vec![]),
        Err(NetError::Timeout) => Attempt::Retry(Cause::Timeout),
        Err(_) => Attempt::Retry(Cause::Server),
    }
}

const _: () = assert!(RESOLVERS.len() <= 64); // `tried` is a u64 bitmask

fn build_resolver(ip: IpAddr) -> TokioResolver {
    let config = ResolverConfig::from_name_servers(vec![NameServerConfig::udp_and_tcp(ip)]);
    let mut b = Resolver::builder_with_config(config, TokioRuntimeProvider::default());
    let o = b.options_mut();
    o.cache_size = 0;
    o.timeout = MAX_TIMEOUT * 2; // outer adaptive timeout always fires first
    o.attempts = 0; // retries are ours, on another server
    b.build().expect("cannot build resolver")
}

/// One server = one resolver = one meter (own adaptive timeout).
struct Server {
    ip: IpAddr,
    resolver: TokioResolver,
    meter: Meter,
    inflight: AtomicUsize,
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
    fn new() -> Self {
        let servers = RESOLVERS
            .iter()
            .map(|&ip| Server {
                ip,
                resolver: build_resolver(ip),
                meter: Meter::default(),
                inflight: 0.into(),
            })
            .collect();
        Self { servers, rr: 0.into() }
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
        let attempt = match tokio::time::timeout(s.meter.timeout(), s.resolver.reverse_lookup(ip)).await {
            Ok(res) => classify(res),
            Err(_) => Attempt::Retry(Cause::Timeout),
        };
        match attempt {
            Attempt::Reply(names) => {
                s.meter.record(t0.elapsed());
                lim.on_success();
                result = Some(names);
                break;
            }
            Attempt::Retry(cause) => {
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

    let pool = Pool::new();
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
