<div align="center">
    <h1>RVSDNS</h1>
    <p>A lightweight and fast tool for performing Reverse DNS lookups.</p>
    <p>Built with Rust.</p>
</div>

## Installation

```bash
wget -qO- https://github.com/cruxthorn/rvsdns/releases/latest/download/rvsdns-linux-x86_64.tar.gz \
  | sudo tar -xz -C /usr/local/bin
```

## Usage

### Examples:

Input is accepted exclusively through STDIN, not as command-line arguments.

```bash
your@pipe:~$ prips <CIDR> | rvsdns
<OUTPUT>

your@redir:~$ rvsdns < IPs.txt
<OUTPUT>

your@str:~$ rvsdns <<< "<IP>"
<OUTPUT>

your@doc:~$ rvsdns << EOF
IP_1
IP_2
EOF
<OUTPUT>

your@sub:~$ rvsdns < <(prips <CIDR>)
<OUTPUT>
```

### Output:

```bash
...
<IP>    abc.domain.tld

Inp: 65536 | Out: 121 | Fail: 0 | Time: 6.140s | Lat: 17.642ms | Con: 203 | Tmo: 13 | Err: 0
  1.1.1.1         Req: 7092 | Tmo: 0 | Err: 0 | Lat: 16.288ms
  8.8.8.8         Req: 7053 | Tmo: 1 | Err: 0 | Lat: 16.323ms
  9.9.9.9         Req: 7024 | Tmo: 1 | Err: 0 | Lat: 16.390ms
  208.67.222.222  Req: 6903 | Tmo: 1 | Err: 0 | Lat: 16.690ms
  94.140.14.14    Req: 5896 | Tmo: 1 | Err: 0 | Lat: 19.731ms
  185.228.168.9   Req: 6383 | Tmo: 3 | Err: 0 | Lat: 18.139ms
  76.76.2.0       Req: 5877 | Tmo: 1 | Err: 0 | Lat: 19.776ms
  64.6.64.6       Req: 5935 | Tmo: 3 | Err: 0 | Lat: 19.503ms
  84.200.69.80    Req: 6937 | Tmo: 1 | Err: 0 | Lat: 16.662ms
  86.54.11.1      Req: 6449 | Tmo: 1 | Err: 0 | Lat: 17.953ms
```
