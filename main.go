// reachable checks whether two servers can reach each other: it ssh's into
// both, and from each one probes the other (DNS, route, ICMP, TCP ports with
// a temporary listener, path MTU, bandwidth).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/dcyber-lab/reachable/internal/probe"
	"github.com/dcyber-lab/reachable/internal/remote"
	"github.com/dcyber-lab/reachable/internal/report"
)

var version = "dev"

const usage = `usage: reachable [flags] HOST_A HOST_B

HOST_A and HOST_B are anything you would pass to ssh: an alias from
~/.ssh/config, user@host, and so on. reachable ssh's into both and checks
A -> B and B -> A.

Exit status: 0 both directions reachable on every tested port, 1 not,
2 usage or ssh error.

flags:
`

func main() {
	os.Exit(run())
}

func run() int {
	var (
		ports     = flag.String("p", "22", "comma-separated TCP ports to test in both directions")
		udpPorts  = flag.String("u", "", "comma-separated UDP ports to test in both directions")
		aAddr     = flag.String("a-addr", "", "address B should dial to reach A (default: A's HostName from ssh -G)")
		bAddr     = flag.String("b-addr", "", "address A should dial to reach B (default: B's HostName from ssh -G)")
		oneWay    = flag.Bool("one-way", false, "only check A -> B")
		count     = flag.Int("c", 5, "pings per direction")
		ctimeout  = flag.Int("t", 3, "TCP connect timeout, seconds")
		trace     = flag.String("trace", "auto", "run tracepath/traceroute: auto (on failure), always, never")
		bw        = flag.Bool("bw", true, "measure bandwidth with iperf3 when both hosts have it")
		iperfPort = flag.Int("iperf-port", 5201, "port for the iperf3 test")
		iperfSecs = flag.Int("iperf-time", 3, "seconds per iperf3 test")
		sshOpts   = flag.String("ssh", "", `extra ssh arguments, e.g. "-p 2222 -i ~/.ssh/key"`)
		asJSON    = flag.Bool("json", false, "print JSON instead of text")
		showVer   = flag.Bool("version", false, "print version")
	)
	flag.Usage = func() {
		fmt.Fprint(os.Stderr, usage)
		flag.PrintDefaults()
	}
	flag.Parse()
	if *showVer {
		fmt.Println(version)
		return 0
	}
	if flag.NArg() != 2 {
		flag.Usage()
		return 2
	}
	if *trace != "auto" && *trace != "always" && *trace != "never" {
		fmt.Fprintln(os.Stderr, "reachable: -trace must be auto, always or never")
		return 2
	}
	portList, err := parsePorts(*ports)
	if err != nil {
		fmt.Fprintln(os.Stderr, "reachable:", err)
		return 2
	}
	udpList, err := parsePorts(*udpPorts)
	if err != nil {
		fmt.Fprintln(os.Stderr, "reachable:", err)
		return 2
	}
	extra := strings.Fields(*sshOpts)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Unix sockets have a ~104 byte path limit; $TMPDIR on macOS eats most
	// of that, so keep the control sockets under /tmp.
	ctlDir, err := os.MkdirTemp("/tmp", "reachable-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "reachable:", err)
		return 2
	}
	defer os.RemoveAll(ctlDir)

	sides := []*probe.Side{
		{Label: "A", Target: flag.Arg(0), Addr: *aAddr},
		{Label: "B", Target: flag.Arg(1), Addr: *bAddr},
	}
	for _, s := range sides {
		if s.Addr == "" {
			if s.Addr, err = remote.Resolve(s.Target, extra); err != nil {
				fmt.Fprintln(os.Stderr, "reachable:", err)
				return 2
			}
		}
		s.Host = remote.New(s.Target, ctlDir, extra)
		// One at a time, so two password prompts don't interleave.
		if err := s.Host.Open(ctx); err != nil {
			fmt.Fprintln(os.Stderr, "reachable:", err)
			return 2
		}
		defer s.Host.Close()
	}

	var wg sync.WaitGroup
	errs := make([]error, len(sides))
	for i, s := range sides {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = s.Gather(ctx)
		}()
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			fmt.Fprintln(os.Stderr, "reachable:", err)
			return 2
		}
	}

	opt := probe.Options{
		Ports:          portList,
		UDPPorts:       udpList,
		PingCount:      *count,
		ConnectTimeout: *ctimeout,
		Trace:          *trace,
		Bandwidth:      *bw,
		IperfPort:      *iperfPort,
		IperfSeconds:   *iperfSecs,
	}
	pr := report.Printer{W: os.Stdout, Color: isTerminal(os.Stdout)}
	if !*asJSON {
		for _, s := range sides {
			pr.Side(s)
		}
	}

	// Directions run one after the other: two iperf3 runs at once would
	// share the link and both numbers would be wrong.
	pairs := [][2]*probe.Side{{sides[0], sides[1]}}
	if !*oneWay {
		pairs = append(pairs, [2]*probe.Side{sides[1], sides[0]})
	}
	var dirs []*probe.Direction
	allOK := true
	for _, pair := range pairs {
		if ctx.Err() != nil {
			return 2
		}
		d := probe.Run(ctx, pair[0], pair[1], opt)
		dirs = append(dirs, d)
		allOK = allOK && d.OK
		if !*asJSON {
			pr.Direction(d)
		}
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(struct {
			Hosts      []*probe.Side      `json:"hosts"`
			Directions []*probe.Direction `json:"directions"`
			OK         bool               `json:"ok"`
		}{sides, dirs, allOK})
	}
	if !allOK {
		return 1
	}
	return 0
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
