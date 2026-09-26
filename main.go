// reachable checks whether two machines can reach each other: it gets onto
// both (over ssh by default), and from each one probes the other (DNS,
// route, ICMP, TCP/UDP ports through a temporary listener, path MTU,
// bandwidth).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/dcyber-lab/reachable/internal/node"
	"github.com/dcyber-lab/reachable/internal/probe"
	"github.com/dcyber-lab/reachable/internal/report"
	"github.com/dcyber-lab/reachable/internal/transport"
)

var version = "dev"

const usage = `usage: reachable [flags] A B

A and B are the two machines, each written as BACKEND://TARGET:

  ssh://web1, web1       over ssh; TARGET is anything ssh takes (an alias
                         from ~/.ssh/config, user@host, ...). The default.
  local://               the machine reachable runs on

reachable gets onto both and checks A -> B and B -> A.

Exit status: 0 every tested port open in every direction, 1 not,
2 bad usage or a machine couldn't be reached. With -json, stdout is JSON
in every case, errors included.

flags:
`

func main() {
	os.Exit(run())
}

type flags struct {
	tcp, udp     string
	aAddr, bAddr string
	oneWay       bool
	count        int
	timeout      time.Duration
	trace        string
	bw           bool
	iperfPort    int
	iperfTime    time.Duration
	locate       bool
	ssh          string
	batch        bool
	json         bool
	verbose      bool
	version      bool
}

func run() int {
	var f flags
	flag.StringVar(&f.tcp, "p", "22", "comma-separated TCP ports to test in both directions")
	flag.StringVar(&f.udp, "u", "", "comma-separated UDP ports to test in both directions")
	flag.StringVar(&f.aAddr, "a-addr", "", "address B should dial to reach A (default: from A's backend, e.g. its ssh HostName)")
	flag.StringVar(&f.bAddr, "b-addr", "", "address A should dial to reach B (default: from B's backend)")
	flag.BoolVar(&f.oneWay, "one-way", false, "only check A -> B")
	flag.IntVar(&f.count, "c", 5, "pings per direction")
	flag.DurationVar(&f.timeout, "t", 3*time.Second, "connect timeout per port")
	flag.StringVar(&f.trace, "trace", "auto", "trace the path: auto (when something failed), always, never")
	flag.BoolVar(&f.bw, "bw", true, "measure bandwidth (iperf3) when both machines can")
	flag.IntVar(&f.iperfPort, "iperf-port", 5201, "port for the bandwidth test")
	flag.DurationVar(&f.iperfTime, "iperf-time", 3*time.Second, "length of each bandwidth test")
	flag.BoolVar(&f.locate, "locate", true, "when a port fails, find where its packets die (needs root or passwordless sudo, tcpdump; bpftrace for more)")
	flag.StringVar(&f.ssh, "ssh", "", `extra ssh arguments, e.g. "-p 2222 -i ~/.ssh/key"`)
	flag.BoolVar(&f.batch, "batch", false, "never prompt (passwords, host keys); implied when stdin is not a terminal")
	flag.BoolVar(&f.json, "json", false, "print JSON (see README for the schema)")
	flag.BoolVar(&f.verbose, "v", false, "show the evidence behind each located drop")
	flag.BoolVar(&f.version, "version", false, "print version")
	flag.Usage = func() {
		fmt.Fprint(os.Stderr, usage)
		flag.PrintDefaults()
	}
	flag.Parse()
	if f.version {
		fmt.Println(version)
		return 0
	}

	out := output{json: f.json, pr: report.Printer{W: os.Stdout, Color: isTerminal(os.Stdout), Verbose: f.verbose}}
	if flag.NArg() != 2 {
		if f.json {
			return out.fail(errors.New("need exactly two machines, A and B"))
		}
		flag.Usage()
		return 2
	}
	opt, err := f.options()
	if err != nil {
		return out.fail(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ssh := &transport.SSH{
		Args:        strings.Fields(f.ssh),
		Interactive: !f.batch && isTerminal(os.Stdin),
	}
	defer ssh.Close()
	backends := node.Registry{
		"ssh":   ssh,
		"local": transport.Local{},
	}

	sides := []*probe.Side{
		{Label: "A", Target: flag.Arg(0), Addr: f.aAddr},
		{Label: "B", Target: flag.Arg(1), Addr: f.bAddr},
	}
	// One at a time, so two password prompts don't interleave.
	for _, s := range sides {
		n, addr, err := backends.Open(ctx, s.Target)
		if err != nil {
			return out.fail(err)
		}
		defer n.Close()
		s.Node = n
		if s.Addr == "" {
			s.Addr = addr
		}
	}

	var wg sync.WaitGroup
	errs := make([]error, len(sides))
	for i, s := range sides {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.Facts, errs[i] = s.Node.Facts(ctx)
			if errs[i] != nil {
				errs[i] = fmt.Errorf("%s (%s): %w", s.Label, s.Target, errs[i])
			}
		}()
	}
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		return out.fail(err)
	}
	for _, s := range sides {
		// The backend couldn't say how to reach this machine (local://
		// can't): take its first address, and let the hint point at the
		// others if that turns out wrong.
		if s.Addr == "" && len(s.Facts.Addrs) > 0 {
			s.Addr = s.Facts.Addrs[0].IP
		}
		if s.Addr == "" {
			return out.fail(fmt.Errorf("%s (%s): no address to dial it at; pass -%s-addr",
				s.Label, s.Target, strings.ToLower(s.Label)))
		}
	}
	out.sides(sides)

	// Directions run one after the other: two bandwidth tests at once
	// would share the link and both numbers would be wrong.
	pairs := [][2]*probe.Side{{sides[0], sides[1]}}
	if !f.oneWay {
		pairs = append(pairs, [2]*probe.Side{sides[1], sides[0]})
	}
	var dirs []*probe.Direction
	allOK := true
	for _, pair := range pairs {
		if ctx.Err() != nil {
			return out.fail(ctx.Err())
		}
		d := probe.Run(ctx, pair[0], pair[1], opt)
		dirs = append(dirs, d)
		allOK = allOK && d.OK
		out.direction(d)
	}
	out.done(sides, dirs, allOK)
	if !allOK {
		return 1
	}
	return 0
}

func (f flags) options() (probe.Options, error) {
	if f.trace != "auto" && f.trace != "always" && f.trace != "never" {
		return probe.Options{}, errors.New("-trace must be auto, always or never")
	}
	tcp, err := parsePorts(f.tcp)
	if err != nil {
		return probe.Options{}, err
	}
	udp, err := parsePorts(f.udp)
	if err != nil {
		return probe.Options{}, err
	}
	return probe.Options{
		TCPPorts:       tcp,
		UDPPorts:       udp,
		PingCount:      f.count,
		ConnectTimeout: f.timeout,
		Trace:          f.trace,
		Bandwidth:      f.bw,
		IperfPort:      f.iperfPort,
		IperfTime:      f.iperfTime,
		Locate:         f.locate,
	}, nil
}

// output writes either text as results come in, or one JSON document at
// the end (or on failure).
type output struct {
	json bool
	pr   report.Printer
}

func (o output) sides(sides []*probe.Side) {
	if !o.json {
		for _, s := range sides {
			o.pr.Side(s)
		}
	}
}

func (o output) direction(d *probe.Direction) {
	if !o.json {
		o.pr.Direction(d)
	}
}

func (o output) done(sides []*probe.Side, dirs []*probe.Direction, ok bool) {
	if o.json {
		o.write(report.Document{SchemaVersion: report.SchemaVersion, OK: ok, Version: version, Hosts: sides, Directions: dirs})
		return
	}
	o.pr.Summary(sides, dirs)
}

func (o output) fail(err error) int {
	if o.json {
		o.write(report.Document{SchemaVersion: report.SchemaVersion, Version: version, Error: err.Error()})
	} else {
		fmt.Fprintln(os.Stderr, "reachable:", err)
	}
	return 2
}

func (o output) write(doc report.Document) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(doc)
}

func parsePorts(s string) ([]int, error) {
	var out []int
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		n, err := strconv.Atoi(f)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("bad port %q", f)
		}
		out = append(out, n)
	}
	return out, nil
}

func isTerminal(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0 && os.Getenv("NO_COLOR") == ""
}
