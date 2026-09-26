package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/dcyber-lab/reachable/internal/probe"
)

func TestSummary(t *testing.T) {
	pmtu := probe.Check{Name: "pmtu", Status: probe.Warn, Code: "pmtu.blackhole", Detail: "1400; PMTU black hole"}
	ab := &probe.Direction{From: "A", To: "B", Result: probe.Partial, Checks: []probe.Check{
		{Name: "tcp/22", Status: probe.OK, Code: "tcp.open", Detail: "open in 2 ms"},
		{Name: "tcp/5432", Status: probe.Fail, Code: "tcp.dropped", Detail: "timed out after 3s: packets dropped (firewall / security group / ACL)"},
		pmtu,
		{Name: "locate tcp/5432", Status: probe.Fail, Code: "drop.dst_ingress", Where: "dst_ingress", Mechanism: "netfilter", Confidence: "observed",
			Culprit: "NETFILTER_DROP in nft_do_chain; iptables-save filter: -A INPUT -p tcp --dport 5432 -j DROP",
			Detail:  "dropped on B before reaching the socket by netfilter (observed): NETFILTER_DROP in nft_do_chain; iptables-save filter: -A INPUT -p tcp --dport 5432 -j DROP",
			Lines:   []string{"B's capture: 9 probe packet(s) in, 0 reply packet(s) out"}},
	}}
	ba := &probe.Direction{From: "B", To: "A", Result: probe.Reachable, OK: true, Checks: []probe.Check{
		{Name: "tcp/22", Status: probe.OK}, {Name: "tcp/5432", Status: probe.OK}, pmtu,
	}}
	sides := []*probe.Side{{Label: "A", Target: "web1"}, {Label: "B", Target: "db1"}}

	var buf bytes.Buffer
	Printer{W: &buf}.Summary(sides, []*probe.Direction{ab, ba})
	out := buf.String()
	for _, want := range []string{
		"A web1 → B db1  PARTIAL     ✓ tcp/22  ✗ tcp/5432",
		"B db1 → A web1  REACHABLE   ✓ tcp/22  ✓ tcp/5432",
		// The located finding replaces the port's guess.
		"✗ tcp/5432  A → B  dropped on B before reaching the socket by netfilter (observed)\n",
		"A out ── network ── B NIC ── B XDP ── B in ✗ ── B socket",
		// The rule before what the kernel said.
		"iptables-save filter: -A INPUT -p tcp --dport 5432 -j DROP\n     kernel: NETFILTER_DROP in nft_do_chain",
		// The same problem both ways is one line.
		"! pmtu      A ⇄ B  1400; PMTU black hole",
		"-v shows the evidence",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("summary lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "firewall / security group / ACL") || strings.Contains(out, "9 probe packet") {
		t.Errorf("summary shows the guess or the evidence:\n%s", out)
	}
	if strings.Count(out, "pmtu") != 1 {
		t.Errorf("pmtu listed more than once:\n%s", out)
	}

	buf.Reset()
	Printer{W: &buf, Verbose: true}.Summary(sides, []*probe.Direction{ab, ba})
	if !strings.Contains(buf.String(), "9 probe packet(s) in") {
		t.Errorf("-v summary lacks the evidence:\n%s", buf.String())
	}
}

func TestStripReply(t *testing.T) {
	got := Printer{}.strip("return_path", "A", "B")
	want := "A out ── network ── B NIC ── B XDP ── B in ── B socket\n     reply B out ── network ✗ ── A in"
	if got != want {
		t.Errorf("strip:\n got %q\nwant %q", got, want)
	}
}
