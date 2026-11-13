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

const MIN_CON: usize = 256;
const START_CON: usize = 512;
const MAX_CON: usize = 4096; // ulimit -n 65535
const MAX_TRIES: usize = 3; // 1 attempt + max 2 retries

const BOOT_TIMEOUT: Duration = Duration::from_millis(1500);
const MIN_TIMEOUT: Duration = Duration::from_millis(800);
const MAX_TIMEOUT: Duration = Duration::from_millis(2500);

const USAGE: &str = "rvsdns - fast reverse DNS lookup (Direct STDIN only)\n";
const RESOLVERS: [IpAddr; 4] = [
    // Cloudflare
    IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
    IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
    // Google
    IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
    IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)),
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
    limit: AtomicUsize,  // target concurrency
    live: AtomicUsize,   // permits that currently exist
    streak: AtomicUsize, // successes since last increase
    con_sum: AtomicU64,
    con_n: AtomicU64,
}

impl Limiter {
    fn new() -> Self {
        Self {
            sem: Semaphore::new(START_CON),
            limit: START_CON.into(),
            live: START_CON.into(),
            streak: 0.into(),
            con_sum: 0.into(),
            con_n: 0.into(),
        }
    }

    /// Returns the permit and the limit observed at start.
    async fn acquire(&self) -> (SemaphorePermit<'_>, usize) {
        let p = self.sem.acquire().await.expect("semaphore never closed");
        let in_flight = self.live.load(Relaxed).saturating_sub(self.sem.available_permits());
        self.con_sum.fetch_add(in_flight as u64, Relaxed);
        self.con_n.fetch_add(1, Relaxed);
        (p, self.limit.load(Relaxed))
    }

    /// Release; surplus permits (after a shrink) are forgotten instead of returned.
    fn release(&self, p: SemaphorePermit<'_>) {
        if self.live.load(Relaxed) > self.limit.load(Relaxed) {
            self.live.fetch_sub(1, Relaxed);
            p.forget();
        }
    }

    /// Additive increase: +1 per `limit` successes.
    fn on_success(&self) {
        let l = self.limit.load(Relaxed);
        if l < MAX_CON && self.streak.fetch_add(1, Relaxed) + 1 >= l {
            self.streak.store(0, Relaxed);
            self.limit.fetch_add(1, Relaxed);
            self.live.fetch_add(1, Relaxed);
            self.sem.add_permits(1);
        }
    }

    /// Multiplicative decrease on any loss signal, once per congestion event.
    fn on_backoff(&self, seen: usize) {
        let _ = self
            .limit
            .compare_exchange(seen, (seen * 7 / 8).max(MIN_CON), Relaxed, Relaxed);
        self.streak.store(0, Relaxed);
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

fn build_resolver() -> TokioResolver {
    let ns = RESOLVERS.iter().map(|&ip| NameServerConfig::udp_and_tcp(ip)).collect();
    let mut b = Resolver::builder_with_config(
        ResolverConfig::from_name_servers(ns),
        TokioRuntimeProvider::default(),
    );
    let o = b.options_mut();
    o.cache_size = 0;
    o.num_concurrent_reqs = 1; // one request per query
    o.timeout = MAX_TIMEOUT * 2; // outer adaptive timeout always fires first
    o.attempts = 0; // retries are ours
    b.build().expect("cannot build resolver")
}

/// `None` = gave up after MAX_TRIES (distinct from a valid "no PTR" reply).
async fn lookup(
    r: &TokioResolver,
    lim: &Limiter,
    meter: &Meter,
    ip: IpAddr,
) -> (IpAddr, Option<Vec<String>>) {
    let (permit, seen) = lim.acquire().await;
    let mut result = None;
    for _ in 0..MAX_TRIES {
        let t0 = Instant::now();
        let attempt = match tokio::time::timeout(meter.timeout(), r.reverse_lookup(ip)).await {
            Ok(res) => classify(res),
            Err(_) => Attempt::Retry(Cause::Timeout),
        };
        match attempt {
            Attempt::Reply(names) => {
                meter.record(t0.elapsed());
                lim.on_success();
                result = Some(names);
                break;
            }
            Attempt::Retry(cause) => {
                meter.fail(cause);
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

    let resolver = build_resolver();
    let (lim, meter) = (Limiter::new(), Meter::default());
    let started = Instant::now();
    let (mut inp, mut out, mut fail) = (0u64, 0u64, 0u64);

    let mut w = BufWriter::new(io::stdout().lock());
    let mut results = pin!(
        ips()
            .map(|ip| lookup(&resolver, &lim, &meter, ip))
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
        meter.avg_ms(),
        lim.avg_con(),
        meter.tmo.load(Relaxed),
        meter.err.load(Relaxed),
    );
}
