<div align="center">
    <h1>RVSDNS</h1>
    <p>A lightweight and fast tool for performing Reverse DNS lookups.</p>
    <p>Built with Rust.</p>
</div>

## Installation

```bash
wget https://github.com/cruxthorn/rvsdns/releases/latest/download/rvsdns
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
192.168.10    abc.domain.tld
192.168.13    bca.domain.tld
192.168.15    cab.domain.tld

Inp: 5 | Out: 3 | Time: 0.016s | Lat: 15.843ms | Con: 5 | Tmo: 0
```
