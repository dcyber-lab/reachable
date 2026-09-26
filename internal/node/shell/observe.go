package shell

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/dcyber-lab/reachable/internal/node"
)

// scriptWithLib returns an observe script with obslib.sh in front of it.
func scriptWithLib(name string) string {
	b, err := scripts.ReadFile("scripts/obslib.sh")
	if err != nil {
		panic(err)
	}
	return string(b) + script(name)
}

func (n *Node) Observe(ctx context.Context, spec node.ObserveSpec) (node.Observation, error) {
	args := []string{string(spec.Proto), itoa(spec.Port), secs(spec.Lifetime), secs(spec.Baseline)}
	if err := checkArgs(args); err != nil {
		return nil, err
	}
	rctx, cancel := context.WithTimeout(ctx, spec.Baseline+60*time.Second)
	defer cancel()
	out, err := n.r.Run(rctx, scriptWithLib("observe-start"), args)
	if err != nil {
		return nil, err
	}
	inv, dir, err := parseObserveStart(out)
	if err != nil {
		return nil, err
	}
	return &observation{n: n, dir: dir, inv: inv}, nil
}

type observation struct {
	n   *Node
	dir string
	inv node.Inventory
}

func (o *observation) Inventory() node.Inventory { return o.inv }

func (o *observation) Stop(ctx context.Context) (node.Observed, error) {
	args := []string{o.dir}
	if err := checkArgs(args); err != nil {
		return node.Observed{}, err
	}
	rctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	out, err := o.n.r.Run(rctx, scriptWithLib("observe-stop"), args)
	if err != nil {
		return node.Observed{}, err
	}
	return parseObserveStop(out)
}

func parseObserveStart(out string) (node.Inventory, string, error) {
	m := kv(out)
	if e := first(m, "err"); e != "" {
		return node.Inventory{}, "", fmt.Errorf("%w: %s", node.ErrUnsupported, e)
	}
	dir := first(m, "dir")
	if dir == "" || first(m, "ready") != "1" {
		return node.Inventory{}, "", fmt.Errorf("observe-start: %s", firstLine(out))
	}
	inv := node.Inventory{Kernel: first(m, "kernel"), Have: m["have"], Missing: m["missing"]}
	for _, h := range m["hook"] {
		f := strings.SplitN(h, "\t", 3)
		for len(f) < 3 {
			f = append(f, "")
		}
		inv.Hooks = append(inv.Hooks, node.Hook{Kind: f[0], Where: f[1], Detail: f[2]})
	}
	for _, r := range m["rpf"] {
		dev, v, _ := strings.Cut(r, " ")
		if inv.RPFilter == nil {
			inv.RPFilter = map[string]int{}
		}
		inv.RPFilter[dev], _ = strconv.Atoi(v)
	}
	if c := strings.Fields(first(m, "ct")); len(c) == 2 {
		inv.ConntrackCount, _ = strconv.Atoi(c[0])
		inv.ConntrackMax, _ = strconv.Atoi(c[1])
	}
	inv.Policies = m["fw"]
	inv.Sysctls = m["sysctl"]
	return inv, dir, nil
}

func parseObserveStop(out string) (node.Observed, error) {
	m := kv(out)
	if e := first(m, "err"); e != "" {
		return node.Observed{}, fmt.Errorf("%s", e)
	}
	var o node.Observed
	if w := strings.Fields(first(m, "window")); len(w) == 2 {
		o.BaselineSecs, _ = strconv.ParseFloat(w[0], 64)
		o.ProbeSecs, _ = strconv.ParseFloat(w[1], 64)
	}
	for _, c := range m["ctr"] {
		f := strings.Split(c, "\t")
		if len(f) != 5 {
			continue
		}
		base, _ := strconv.ParseInt(f[3], 10, 64)
		delta, _ := strconv.ParseInt(f[4], 10, 64)
		o.Counters = append(o.Counters, node.Counter{Kind: f[0], Scope: f[1], Name: f[2], Baseline: base, Delta: delta})
	}
	for _, l := range m["pkt"] {
		if p, ok := parsePacket(l); ok {
			o.Packets = append(o.Packets, p)
		}
	}
	for _, d := range m["drop"] {
		f := strings.Fields(d)
		if len(f) < 6 {
			continue
		}
		sp, _ := strconv.Atoi(f[1])
		dp, _ := strconv.Atoi(f[3])
		reason := f[5]
		if reason == "-" {
			reason = ""
		}
		o.Drops = append(o.Drops, node.Drop{Src: f[0], SrcPort: sp, Dst: f[2], DstPort: dp, Location: f[4], Reason: reason,
			OtherNetns: len(f) > 6 && f[6] == "other"})
	}
	return o, nil
}

// parsePacket reads one line of `tcpdump -nn -tt -i any`. Newer tcpdumps
// print the device and direction before the protocol, older ones don't:
//
//	1790392127.309615 dB    In  IP 10.9.0.1.51878 > 10.9.0.2.8080: Flags [S], seq ...
//	1790392127.309615 IP 10.9.0.1.40000 > 10.9.0.2.5353: UDP, length 16
//	1790392127.309615 IP 10.9.0.254 > 10.9.0.1: ICMP host 10.9.0.2 unreachable - admin prohibited filter, length 72
//	1790392127.309615 IP6 fd00:9::1.51878 > fd00:9::2.8080: Flags [S.], ...
func parsePacket(line string) (node.Packet, bool) {
	f := strings.Fields(line)
	var p node.Packet
	if len(f) < 5 {
		return p, false
	}
	p.Time, _ = strconv.ParseFloat(f[0], 64)
	i := 1
	for i < len(f) && f[i] != "IP" && f[i] != "IP6" {
		i++
	}
	if i+3 >= len(f) || f[i+2] != ">" {
		return p, false
	}
	if i == 3 {
		p.Dev, p.Dir = f[1], f[2]
	}
	src, dst := f[i+1], strings.TrimSuffix(f[i+3], ":")
	rest := strings.Join(f[i+4:], " ")
	switch {
	case strings.HasPrefix(rest, "ICMP"):
		p.Proto, p.Src, p.Dst = "icmp", src, dst
		p.Info = strings.TrimSuffix(strings.SplitN(rest, ", length", 2)[0], ",")
		return p, true
	case strings.HasPrefix(rest, "Flags ["):
		p.Proto = "tcp"
		p.Flags = strings.TrimPrefix(strings.SplitN(rest, "]", 2)[0], "Flags [")
	case strings.HasPrefix(rest, "UDP"):
		p.Proto = "udp"
	default:
		return p, false
	}
	var ok1, ok2 bool
	p.Src, p.SrcPort, ok1 = splitHostPort(src)
	p.Dst, p.DstPort, ok2 = splitHostPort(dst)
	return p, ok1 && ok2
}

// splitHostPort splits tcpdump's addr.port, where the port follows the
// last dot for both IPv4 and IPv6.
func splitHostPort(s string) (string, int, bool) {
	i := strings.LastIndexByte(s, '.')
	if i < 0 {
		return s, 0, false
	}
	port, err := strconv.Atoi(s[i+1:])
	return s[:i], port, err == nil
}
