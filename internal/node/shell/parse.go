package shell

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dcyber-lab/reachable/internal/node"
)

// The scripts talk back in key=value lines; kv parses them. Repeated keys
// keep every value in order.
func kv(s string) map[string][]string {
	m := map[string][]string{}
	for _, line := range strings.Split(s, "\n") {
		if k, v, ok := strings.Cut(strings.TrimRight(line, "\r"), "="); ok {
			m[k] = append(m[k], v)
		}
	}
	return m
}

func first(m map[string][]string, k string) string {
	if v := m[k]; len(v) > 0 {
		return v[0]
	}
	return ""
}

func parseFacts(s string) (node.Facts, map[string]bool) {
	m := kv(s)
	f := node.Facts{
		Hostname: first(m, "hostname"),
		Arch:     first(m, "arch"),
		Kernel:   first(m, "kernel"),
		User:     first(m, "user"),
	}
	tools := map[string]bool{}
	for _, t := range m["tool"] {
		tools[t] = true
		f.Capabilities = append(f.Capabilities, t)
	}
	sort.Strings(f.Capabilities)
	for _, a := range m["addr"] {
		ip, dev, _ := strings.Cut(a, " ")
		f.Addrs = append(f.Addrs, node.Addr{IP: ip, Dev: dev})
	}
	return f, tools
}

// parseRoute reads the first line of `ip route get` plus the device's MTU.
func parseRoute(line string, mtu string) node.Route {
	var r node.Route
	f := strings.Fields(line)
	for i := 0; i+1 < len(f); i++ {
		switch f[i] {
		case "dev":
			r.Dev = f[i+1]
		case "src":
			r.Src = f[i+1]
		case "via":
			r.Via = f[i+1]
		}
	}
	r.MTU, _ = strconv.Atoi(strings.TrimSpace(mtu))
	return r
}

var (
	pingCounts = regexp.MustCompile(`(\d+) packets transmitted, (\d+) (?:packets )?received`)
	pingRTT    = regexp.MustCompile(`= [\d.]+/([\d.]+)/`)
)

func parsePing(out string) (node.Ping, bool) {
	var p node.Ping
	m := pingCounts.FindStringSubmatch(out)
	if m == nil {
		return p, false
	}
	p.Sent, _ = strconv.Atoi(m[1])
	p.Received, _ = strconv.Atoi(m[2])
	if r := pingRTT.FindStringSubmatch(out); r != nil {
		p.AvgMS, _ = strconv.ParseFloat(r[1], 64)
	}
	return p, true
}

// parseConnect reads connect.sh's rc=, ms= and err= lines.
func parseConnect(out string) node.Dial {
	m := kv(out)
	rc, _ := strconv.Atoi(first(m, "rc"))
	ms, _ := strconv.Atoi(first(m, "ms"))
	d := node.Dial{Elapsed: time.Duration(ms) * time.Millisecond, Msg: first(m, "err")}
	// bash prefixes errors with "bash: connect: " / "bash: line 1: ...".
	if i := strings.LastIndex(d.Msg, ": "); i >= 0 {
		d.Msg = d.Msg[i+2:]
	}
	low := strings.ToLower(d.Msg)
	switch {
	case first(m, "rc") == "":
		d.Outcome, d.Msg = node.Failed, "no result from connect script"
	case rc == 0:
		d.Outcome = node.Open
	case rc == 124:
		d.Outcome = node.Timeout
	case strings.Contains(low, "refused"):
		d.Outcome = node.Refused
	case strings.Contains(low, "no route"), strings.Contains(low, "unreachable"):
		d.Outcome = node.Unreachable
	default:
		d.Outcome = node.Failed
	}
	return d
}

// parseUDP reads udp.sh's sent=, reply= and err= lines.
func parseUDP(out string) node.Dial {
	m := kv(out)
	msg := first(m, "err")
	switch {
	case first(m, "sent") != "1":
		if msg == "" {
			msg = "no result from udp script"
		}
		return node.Dial{Outcome: node.Failed, Msg: msg}
	case first(m, "reply") == "pong":
		return node.Dial{Outcome: node.Open}
	case strings.Contains(strings.ToLower(msg), "refused"):
		return node.Dial{Outcome: node.Refused, Msg: msg}
	case msg != "":
		return node.Dial{Outcome: node.Failed, Msg: msg}
	default:
		return node.Dial{Outcome: node.Timeout}
	}
}

func parsePMTU(out string) (node.PMTU, error) {
	m := kv(out)
	if e := first(m, "err"); e != "" {
		return node.PMTU{}, fmt.Errorf("%s", e)
	}
	n, err := strconv.Atoi(first(m, "pmtu"))
	if err != nil {
		return node.PMTU{}, fmt.Errorf("no result from pmtu script")
	}
	how := map[string]node.PMTUMethod{
		"iface":  node.PMTUInterface,
		"icmp":   node.PMTUReported,
		"search": node.PMTUProbed,
	}[first(m, "how")]
	return node.PMTU{Bytes: n, Method: how}, nil
}

func parseIperf(out string) (float64, error) {
	var r struct {
		Error string `json:"error"`
		End   struct {
			SumReceived struct {
				BitsPerSecond float64 `json:"bits_per_second"`
			} `json:"sum_received"`
		} `json:"end"`
	}
	start := strings.Index(out, "{")
	if start < 0 {
		return 0, fmt.Errorf("%s", firstLine(out))
	}
	if err := json.Unmarshal([]byte(out[start:]), &r); err != nil {
		return 0, fmt.Errorf("unreadable iperf3 output: %v", err)
	}
	if r.Error != "" {
		return 0, fmt.Errorf("%s", r.Error)
	}
	return r.End.SumReceived.BitsPerSecond, nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
