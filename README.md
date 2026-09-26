# reachable

Can server A talk to server B, and B to A? `reachable` ssh's into both and
probes each direction from the inside, so the answer is about the path
between the two servers, not between your laptop and each of them.

```
$ reachable -p 22,5432 web1 db1
A  web1  deploy@web1  x86_64 6.8.0
   dialed as 10.0.1.12; addrs: 10.0.1.12@eth0
   tools: getent ip iperf3 ping python3 ss timeout tracepath
B  db1  deploy@db1  x86_64 6.8.0
   dialed as 10.0.2.7; addrs: 10.0.2.7@eth0
   tools: getent ip ping python3 ss timeout

A -> B  10.0.2.7
  ok    route     dev eth0 src 10.0.1.12 via 10.0.1.1, mtu 9001
  ok    icmp      5/5 replies, avg 0.41 ms
  ok    tcp/22    open in 2 ms (existing service on B)
  fail  tcp/5432  timed out after 3s: packets dropped (firewall / security group / ACL)
  warn  pmtu      1500; bigger packets vanish without ICMP frag-needed: PMTU black hole, ...
  skip  bw        not measured while ports are blocked
  info  trace     A -> 10.0.2.7
               1?: [LOCALHOST]                      pmtu 9001
               ...
  => PARTIAL: tcp/22 open, tcp/5432 blocked
...
```

## Install

Binaries for Linux and macOS (amd64, arm64) are on the
[releases page](https://github.com/dcyber-lab/reachable/releases), or:

```
go install github.com/dcyber-lab/reachable@latest
```

Only the machine you run it from needs the binary. The servers need bash
and whatever of `ip`, `ping`, `ss`, `python3`/`socat`/`nc`, `tracepath`,
`iperf3` they happen to have: every check that lacks its tool is reported
as `skip` instead of failing. Nothing is installed or left behind on them.

## Usage

```
reachable [flags] HOST_A HOST_B
```

`HOST_A` / `HOST_B` are whatever you'd give `ssh`: an alias from
`~/.ssh/config`, `user@host`, ... It runs the system `ssh`, so `ProxyJump`,
agents, certificates and known_hosts work as usual. One master connection
per host is opened first on your terminal (answer password / 2FA prompts
there), everything after is multiplexed over it.

| flag | default | |
|---|---|---|
| `-p` | `22` | TCP ports to test, comma-separated, both directions |
| `-u` | | UDP ports to test, same |
| `-b-addr` / `-a-addr` | HostName from `ssh -G` | address A dials to reach B / B dials to reach A |
| `-one-way` | off | only A -> B |
| `-c` | 5 | pings per direction |
| `-t` | 3 | TCP connect timeout (s) |
| `-trace` | `auto` | tracepath/traceroute: `auto` (only when something failed), `always`, `never` |
| `-bw` | on | iperf3 bandwidth, when both hosts have iperf3 |
| `-iperf-port` / `-iperf-time` | 5201 / 3 | |
| `-ssh` | | extra ssh args, e.g. `"-p 2222 -i ~/.ssh/key"` |
| `-json` | off | machine-readable output |

Exit status: `0` every tested port is open in every direction, `1` not,
`2` bad usage or ssh couldn't get in.

**The address matters.** By default A dials whatever `HostName` B has in
your ssh config. If you reach B through a bastion or on a public IP, that
is probably not the address A uses; pass the private one with `-b-addr`.
When a direction fails, the report lists the other side's interface
addresses as a hint.

## What each check means

- **dns** — only when the address is a name: what it resolves to *on the
  source server*. Warns if your machine resolves it differently
  (split-horizon DNS).
- **addr** — the dialed IP isn't on any interface of the destination:
  NAT, a floating IP or a load balancer is in front of it.
- **route** — `ip route get`: interface, source address, gateway, MTU.
- **icmp** — ping. Downgraded to a warning when TCP gets through anyway.
- **tcp/N** — the useful one. If nothing listens on N at the destination,
  a temporary listener (python3, else socat, else nc) is started there
  for a few seconds, so:
  - `open` means the SYN really arrived at the destination; with python3
    or socat the listener also reports the source address it saw, which
    exposes SNAT;
  - connected but the listener saw nothing means something in the middle
    answered for the destination (proxy, DNAT, wrong host with the IP);
  - `timed out` is a silent drop (firewall, security group, ACL);
  - `refused` while our listener was up is a REJECT rule in between.

  Ports below 1024 need root for the listener; without one, `refused` still
  proves packets reach the destination's kernel.
- **udp/N** — UDP has no handshake, so the only proof is a listener
  (python3 or socat) on the destination receiving the probe; it answers,
  which tests the way back too. Reply came back: fine. Arrived but no
  reply: the return path filters UDP (stateful firewall, asymmetric
  route). Never arrived: dropped. ICMP port-unreachable while our listener
  was up: a REJECT rule. A port something already holds can't be checked
  and is reported as `skip`.
- **pmtu** — the biggest DF packet that gets through. If bigger ones get
  an ICMP "fragmentation needed" back, fine; if they vanish silently it is
  a PMTU black hole, the classic "ssh works but scp/https hangs".
- **bw** — one iperf3 TCP run per direction, on `-iperf-port`. The two
  directions run one after another so they don't share the link.
- **trace** — tracepath/traceroute from the source, by default only when
  something failed.

IPv4 and IPv6 both work: pass a v6 address to `-a-addr` / `-b-addr`, or
a name that resolves to one.

## Development

```
make test    # go vet + unit tests
make lint    # shellcheck
make e2e     # end-to-end, needs root (sudo)
```

`make e2e` builds two network namespaces joined by a veth pair, runs sshd
in each, and checks reachable's verdicts against faults injected with
iptables: DROP and REJECT for TCP and UDP, SNAT, a REDIRECT that answers
for the destination, a UDP return path filter, filtered ICMP, a PMTU black
hole, a destination with no route, DNS on the source, IPv6, and the socat
and nc listener fallbacks. CI runs it on every push, with IPv6 required.

Releases: push a `v*` tag and goreleaser builds and publishes them.

The remote side is plain bash in `internal/probe/scripts/`, embedded in the
binary and fed to `ssh host bash -s`. Each script wraps its body in
`main ... </dev/null` so nothing it runs can swallow the rest of the script
from stdin.
