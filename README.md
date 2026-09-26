# reachable

Can machine A talk to machine B, and B to A? `reachable` gets onto both
and probes each direction from the inside, so the answer is about the path
between the two machines, not between your laptop and each of them. When
something is in the way it says what: a dropping firewall, a REJECT rule,
SNAT, a proxy answering for the destination, a PMTU black hole, a filtered
UDP return path.

It is built to be called by programs as much as by people: `-json` gives a
versioned document with a stable code for every finding, it never waits for
input when nobody is at the terminal, and how it reaches machines is a
pluggable backend (ssh today).

```
$ reachable -p 22,5432 web1 db1
A  web1  deploy@web1  x86_64 6.8.0
   dialed as 10.0.1.12; addrs: 10.0.1.12@eth0
   can use: getent ip iperf3 ping python3 ss timeout tracepath
B  db1  deploy@db1  x86_64 6.8.0
   dialed as 10.0.2.7; addrs: 10.0.2.7@eth0
   can use: getent ip ping python3 ss timeout

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

Only the machine you run it from needs the binary. With the ssh and local
backends the probed machines need bash and whatever of `ip`, `ping`, `ss`,
`python3`/`socat`/`nc`, `tracepath`, `iperf3` they happen to have: a check
whose tool is missing is reported as `skip`, not as a failure. Nothing is
installed, and every process started for a probe is killed when it's done.

## Usage

```
reachable [flags] A B
```

A and B are written `BACKEND://TARGET`:

| | |
|---|---|
| `web1`, `ssh://web1`, `ssh://deploy@10.0.1.12` | over ssh, the default. TARGET is anything `ssh` accepts; the system `ssh` is used, so `~/.ssh/config`, `ProxyJump`, agents and certificates work as usual. |
| `local://` | the machine reachable runs on |

| flag | default | |
|---|---|---|
| `-p` | `22` | TCP ports to test, comma-separated, both directions |
| `-u` | | UDP ports to test, same |
| `-b-addr` / `-a-addr` | from the backend | address A dials to reach B / B dials to reach A |
| `-one-way` | off | only A -> B |
| `-c` | 5 | pings per direction |
| `-t` | 3s | connect timeout per port |
| `-trace` | `auto` | tracepath/traceroute: `auto` (only when something failed), `always`, `never` |
| `-bw` | on | iperf3 bandwidth, when both machines can |
| `-iperf-port` / `-iperf-time` | 5201 / 3s | |
| `-ssh` | | extra ssh args, e.g. `"-p 2222 -i ~/.ssh/key"` |
| `-batch` | when stdin isn't a terminal | never prompt for passwords or host keys; fail instead |
| `-json` | off | machine-readable output, see below |

Exit status: `0` every tested port is open in every direction, `1` not,
`2` bad usage or a machine couldn't be reached.

**The address matters.** By default A dials what B's backend says B is
called; for ssh that's B's `HostName` in your ssh config. If you reach B
through a bastion or on a public IP, that is probably not the address A
uses: pass the private one with `-b-addr`. `local://` can't know, and
takes its first interface address. When a direction fails, the report lists
the other machine's addresses as a hint.

IPv4 and IPv6 both work: pass a v6 address, or a name that resolves to one.

## Calling it from a program (or an AI agent)

```
reachable -json -batch -p 443 -u 53 web1 db1
```

stdout is always one JSON document, errors included, so there is nothing
to scrape:

```jsonc
{
  "schema_version": 1,        // bumped on incompatible changes
  "ok": false,                // same as exit status 0
  "error": "...",             // only when a machine couldn't be reached (exit 2)
  "hosts": [ { "label": "A", "target": "web1", "addr": "10.0.1.12",
               "facts": { "hostname": "...", "addrs": [ {"ip": "...", "dev": "..."} ], ... } }, ... ],
  "directions": [
    {
      "from": "A", "to": "B", "target": "db1.internal", "ip": "10.0.2.7",  // target: what A dialed
      "result": "partial",    // reachable | partial | blocked | unreachable
      "ok": false,
      "verdict": "PARTIAL: tcp/443 open, udp/53 blocked",
      "checks": [
        { "name": "udp/53", "status": "fail", "code": "udp.dropped", "detail": "..." },
        ...
      ]
    }
  ]
}
```

Act on `result`, `status` and `code`; `detail` and `verdict` are prose for
people and may be reworded. `status` is `ok`, `warn`, `fail`, `skip` (could
not check) or `info`.

## What each check means

Codes for `tcp/N` and `udp/N` start with `tcp.` / `udp.`. Any check can
also come back as `<name>.unsupported` (skip: the machine can't do it, the
detail says why) or `<name>.error`.

- **dns** — only when the address is a name: what it resolves to *on the
  source machine*. `dns.ok`, `dns.split_horizon` (your machine resolves it
  differently), `dns.unresolved`.
- **addr** — `addr.not_local`: the dialed IP isn't on any interface of the
  destination, so NAT, a floating IP or a load balancer is in front of it.
- **route** — interface, source address, gateway, MTU. `route.ok`,
  `route.none`.
- **icmp** — ping. `icmp.ok`, `icmp.loss`, `icmp.no_reply`, and
  `icmp.filtered` (a warning) when no ping gets through but ports do.
- **tcp/N** — if nothing listens on N at the destination, a temporary
  listener is started there first, so:
  - `tcp.open`: the connection really arrived at the destination;
  - `tcp.snat`: it did, from a different source address than the
    source machine's own (SNAT in between);
  - `tcp.intercepted`: something connected, but our listener never saw it:
    a proxy, DNAT, or another host answering for that address;
  - `tcp.dropped`: timed out, a silent drop (firewall, security group, ACL);
  - `tcp.rejected`: refused while our listener was up, a REJECT rule;
  - `tcp.refused`: refused although a service listens there (bound to
    another address, or a REJECT rule);
  - `tcp.refused_no_listener`: nothing listens and no listener could be
    started (ports below 1024 need root); packets do get there.
- **udp/N** — UDP has no handshake, so the only proof is our listener on
  the destination receiving the probe; it answers, which tests the way back.
  `udp.open`, `udp.snat`, `udp.reply_filtered` (arrived, the answer didn't
  come back: stateful firewall, asymmetric route), `udp.dropped`,
  `udp.rejected` (ICMP port-unreachable while we listened),
  `udp.intercepted`, `udp.in_use` (skip: something else holds the port, so
  there's nothing to check against).
- **pmtu** — the biggest packet that crosses with DF set. `pmtu.ok`,
  `pmtu.reported` (smaller than the interface MTU, but a hop says so and
  PMTUD works), `pmtu.blackhole` (bigger packets vanish silently: the
  classic "ssh works, scp hangs"), `pmtu.skipped` (ICMP is filtered).
- **bw** — one iperf3 TCP run per direction, on `-iperf-port`, one
  direction at a time. `bw.ok`, `bw.skipped` (ports blocked).
- **trace** — hops from the source, by default only when something failed.
  `trace.hops`, `trace.silent`.
- **hint** — `hint.other_addrs`: nothing got through; the destination's
  other addresses, in case the wrong one was dialed.

## How it's built

```
main.go                  CLI: flags, output
internal/probe           the diagnosis: which checks, in what order, what a
                         combination of results means. Knows only node.Node.
internal/node            node.Node: what a machine must be able to do
                         (Facts, Resolve, Route, Ping, Dial, Listen, PMTU,
                         Trace, bandwidth), with typed results; and the
                         BACKEND:// registry.
internal/node/shell      a node.Node made of bash scripts, run through a
                         shell.Runner ("run this script, give me stdout")
internal/transport       Runners and backends: ssh, local
```

The diagnosis never sees how a probe was carried out, only its result
(`Dial{Outcome: Timeout}`, a listener that saw a peer or didn't, ...), so
the ways of reaching machines can change without touching it. There are two
places to plug in:

- **A new Runner**, for anything that can run a bash script on a machine
  and hand back its stdout: `docker exec`, `kubectl exec`, a job system, a
  service that dispatches a script to its agents and returns the report.
  All the existing probes come for free. Implement `shell.Runner` (`Run`,
  `Start` for the few long-lived scripts, `Close`) and register a backend
  that wraps it in `shell.New`; `transport/local.go` is the smallest example.
- **A new Node**, when the machine side isn't bash: a native agent that
  probes in-process, or a service with its own probe API. Implement
  `node.Node` and register a `node.Backend` for its scheme. Report "can't
  do that here" as `node.ErrUnsupported`, a taken port as `node.ErrInUse`.

`internal/probe/probe_test.go` drives the diagnosis with a scripted fake
Node, which is also the quickest way to see what each method is expected
to return.

## Development

```
make test    # go vet + unit tests
make lint    # shellcheck
make e2e     # end-to-end, needs root (sudo)
```

`make e2e` builds two network namespaces joined by a veth pair, runs sshd
in each, and checks the codes reachable reports against faults injected
with iptables: DROP and REJECT for TCP and UDP, SNAT, a REDIRECT that
answers for the destination, a UDP return path filter, filtered ICMP, a PMTU
black hole, a destination with no route, DNS on the source, IPv6, the
`local://` backend, unreachable machines, back-to-back reruns, and the
socat and nc listener fallbacks. CI runs it on every push, with IPv6
required.

The shell node's scripts are in `internal/node/shell/scripts/`, embedded in
the binary and fed to `bash -s`. Each wraps its body in `main ... </dev/null`
so nothing it runs can swallow the rest of the script from stdin, always
exits 0 (a non-zero exit is the Runner's own failure), and reports through
`key=value` lines on stdout.

Releases: push a `v*` tag and goreleaser builds and publishes them.
