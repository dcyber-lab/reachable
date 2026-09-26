#!/usr/bin/env bash
# e2e.sh -- run reachable against a two-namespace lab (see lab.sh) with
# faults injected, and assert on its JSON output. Needs root.
#
#   REACHABLE=path   binary to test (default: go build)
#   REQUIRE_IPV6=1   fail instead of skipping when the kernel has no IPv6
set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d /tmp/reachable-e2e.XXXXXX)
bin=${REACHABLE:-}
if [ -z "$bin" ]; then
	bin=$work/reachable
	(cd "$here/../.." && go build -o "$bin" .) || exit 1
fi

cleanup() { "$here/lab.sh" down "$work"; [ -n "${KEEP:-}" ] || rm -rf "$work"; }
trap cleanup EXIT
"$here/lab.sh" up "$work" || exit 1

ns() { ip netns exec "$@"; }
has_v6() { [ -d /proc/sys/net/ipv6 ]; }
reset() {
	for n in ha hb; do
		ns "$n" iptables -F
		ns "$n" iptables -t nat -F
		has_v6 && ns "$n" ip6tables -F
	done
	return 0
}

fails=0
# scenario NAME "reachable args, machines included" EXPR... -- run, then assert
scenario() {
	local name=$1 args=$2
	shift 2
	echo "--- $name"
	# shellcheck disable=SC2086 # args is a word list on purpose
	"$bin" -json -ssh "-F $work/ssh_config" $args >"$work/$name.json" 2>"$work/$name.err" </dev/null
	local rc=$?
	if ! python3 "$here/check.py" "$work/$name.json" "$rc" "$@"; then
		fails=$((fails + 1))
		echo "    exit $rc; stderr:"; sed 's/^/      /' "$work/$name.err"
		python3 -m json.tool "$work/$name.json" | sed 's/^/      /'
	fi
}
data="-a-addr 10.9.0.1 -b-addr 10.9.0.2"
scripts=$here/../../internal/node/shell/scripts

reset
scenario clean "$data -p 22,8080 -u 5353 -iperf-time 1s ha hb" \
	'rc == 0' 'd["ok"]' \
	'st(0, "tcp/22") == "ok" and "existing service" in det(0, "tcp/22")' \
	'st(0, "tcp/8080") == "ok" and "temporary listener" in det(0, "tcp/8080")' \
	'st(1, "tcp/8080") == "ok"' \
	'st(0, "udp/5353") == "ok" and "reply came back" in det(0, "udp/5353")' \
	'st(1, "udp/5353") == "ok"' \
	'st(0, "icmp") == "ok" and st(0, "pmtu") == "ok" and det(0, "pmtu") == "1500"' \
	'st(0, "bw") == "ok" and st(1, "bw") == "ok"' \
	'st(0, "trace") == ""' \
	'verdict(0) == "REACHABLE on tcp/22,tcp/8080,udp/5353"'

reset
ns ha ip addr add 10.9.0.11/24 dev dA 2>/dev/null
ns ha iptables -t nat -A POSTROUTING -o dA -p tcp --dport 6060 -j SNAT --to-source 10.9.0.11
ns ha iptables -t nat -A POSTROUTING -o dA -p udp --dport 6061 -j SNAT --to-source 10.9.0.11
ns hb iptables -t nat -A PREROUTING -i dB -p tcp --dport 7070 -j REDIRECT --to-ports 22
ns hb iptables -A INPUT -i dB -p tcp --dport 8080 -j DROP
ns hb iptables -A INPUT -i dB -p tcp --dport 9090 -j REJECT --reject-with tcp-reset
ns hb iptables -A INPUT -i dB -p udp --dport 5353 -j DROP
ns hb iptables -A INPUT -i dB -p udp --dport 5454 -j REJECT --reject-with icmp-port-unreachable
ns ha iptables -A INPUT -i dA -p udp --sport 5555 -j DROP # B's replies
ns hb iptables -A INPUT -i dB -p icmp --icmp-type echo-request -j DROP
scenario faults "$data -p 22,6060,7070,8080,9090 -u 5353,5454,5555,6061 -bw=false -trace never ha hb" \
	'rc == 1' 'not d["ok"]' \
	'st(0, "icmp") == "warn" and "ICMP is filtered" in det(0, "icmp")' \
	'st(0, "tcp/22") == "ok"' \
	'code(0, "tcp/6060") == "tcp.snat" and "10.9.0.11" in det(0, "tcp/6060")' \
	'st(0, "tcp/7070") == "warn" and code(0, "tcp/7070") == "tcp.intercepted"' \
	'code(0, "tcp/8080") == "tcp.dropped"' \
	'code(0, "tcp/9090") == "tcp.rejected"' \
	'code(0, "udp/5353") == "udp.dropped"' \
	'code(0, "udp/5454") == "udp.rejected"' \
	'st(0, "udp/5555") == "warn" and code(0, "udp/5555") == "udp.reply_filtered"' \
	'code(0, "udp/6061") == "udp.snat"' \
	'st(0, "pmtu") == "skip"' \
	'd["directions"][0]["result"] == "partial"' \
	'd["directions"][1]["ok"] and st(1, "icmp") == "ok"'

# Straight after a run whose listeners saw nothing (so they'd otherwise
# linger until their timeout), a rerun must find the ports free again.
reset
ns hb iptables -A INPUT -i dB -p tcp --dport 8080 -j DROP
ns hb iptables -A INPUT -i dB -p udp --dport 5353 -j DROP
for run in 1 2; do
	scenario "rerun-$run" "$data -p 8080 -u 5353 -bw=false -trace never -one-way ha hb" \
		'rc == 1' 'code(0, "tcp/8080") == "tcp.dropped"' 'code(0, "udp/5353") == "udp.dropped"'
done
if ns hb ss -Hlntu | grep -qE ':(8080|5353) '; then
	echo "--- leftovers: listeners still up on hb after the run"; fails=$((fails + 1))
fi

reset
ns hb iptables -A INPUT -i dB -m length --length 1401:65535 -j DROP
scenario blackhole "$data -p 22 -bw=false -one-way ha hb" \
	'rc == 0' \
	'code(0, "pmtu") == "pmtu.blackhole" and det(0, "pmtu").startswith("1400")'

reset
scenario dns "-a-addr 10.9.0.1 -b-addr hb.lab -p 22 -bw=false -one-way ha hb" \
	'rc == 0' \
	'st(0, "dns") == "ok" and "10.9.0.2" in det(0, "dns")' \
	'd["directions"][0]["ip"] == "10.9.0.2"'

scenario noroute "-p 22 -bw=false -one-way -trace never ha hb" \
	'rc == 1' \
	'd["directions"][0]["target"] == "10.8.2.2"' \
	'code(0, "route") == "route.none"' \
	'st(0, "hint") == "info" and "10.9.0.2" in det(0, "hint")' \
	'd["directions"][0]["result"] == "unreachable"'

# The local backend: A is the machine the tests run on (the root
# namespace), which reaches hb over its management link.
reset
scenario local "-a-addr 10.8.2.1 -b-addr 10.8.2.2 -p 22,8080 -u 5353 -bw=false -trace never local:// hb" \
	'rc == 0' 'd["ok"]' \
	'd["hosts"][0]["target"] == "local://"' \
	'code(0, "tcp/8080") == "tcp.open" and code(1, "tcp/8080") == "tcp.open"' \
	'code(0, "udp/5353") == "udp.open"'

# Failures to get onto a machine still give JSON on stdout, exit 2.
scenario unknown-backend "nope://x hb" \
	'rc == 2' 'not d["ok"]' 'd["schema_version"] == 1' '"unknown backend" in d["error"]'
scenario ssh-down "-p 22 ha root@10.8.1.99" \
	'rc == 2' 'not d["ok"]' 'd["error"].startswith("ssh root@10.8.1.99")'

if has_v6; then
	reset
	ns hb ip6tables -A INPUT -i dB -p tcp --dport 8081 -j DROP
	scenario ipv6 "-a-addr fd00:9::1 -b-addr fd00:9::2 -p 22,8080,8081 -u 5353 -bw=false -trace never ha hb" \
		'rc == 1' \
		'st(0, "route") == "ok" and st(0, "icmp") == "ok"' \
		'st(0, "tcp/22") == "ok"' \
		'st(0, "tcp/8080") == "ok" and "temporary listener" in det(0, "tcp/8080")' \
		'st(0, "tcp/8081") == "fail" and "timed out" in det(0, "tcp/8081")' \
		'st(0, "udp/5353") == "ok" and "reply came back" in det(0, "udp/5353")' \
		'st(0, "pmtu") == "ok" and det(0, "pmtu") == "1500"' \
		'd["directions"][1]["ok"]'
elif [ "${REQUIRE_IPV6:-}" = 1 ]; then
	echo "--- ipv6: this kernel has no IPv6, and REQUIRE_IPV6=1"
	fails=$((fails + 1))
else
	echo "--- ipv6: skipped, this kernel has no IPv6"
fi

# The listener falls back to socat, then nc, when python3 is missing.
# Hide python3 by running the script with a PATH of hand-picked tools.
reset
fb=$work/fallback-bin
mkdir -p "$fb"
for t in bash timeout sleep ss; do ln -sf "$(command -v "$t")" "$fb/$t"; done
listen() { # listen TOOL PROTO PORT -- with only TOOL to listen with
	rm -f "$fb/socat" "$fb/nc"
	ln -sf "$(command -v "$1")" "$fb/$1"
	ns hb env PATH="$fb" bash -s -- "$2" "$3" 4 4 <"$scripts/listen.sh" >"$work/listen.out" &
	sleep 0.6
}
fallback() { # fallback NAME PROBE-SCRIPT PORT WANT-PROBE-LINE WANT-LISTENER-LINE...
	local name=$1 probe=$2 port=$3 want=$4 out
	shift 4
	out=$(ns ha bash -s -- 10.9.0.2 "$port" 2 <"$scripts/$probe.sh")
	wait
	echo "--- fallback $name"
	for w in "$@"; do
		grep -qx "$w" "$work/listen.out" && continue
		echo "    FAILED: listener said $(tr '\n' '|' <"$work/listen.out"), want $w"
		fails=$((fails + 1))
	done
	grep -qx "$want" <<<"$out" && return
	echo "    FAILED: probe said $(tr '\n' '|' <<<"$out"), want $want"
	fails=$((fails + 1))
}
listen socat tcp 8181 && fallback socat-tcp connect 8181 "rc=0" "READY socat" "PEER 10.9.0.1"
listen socat udp 8182 && fallback socat-udp udp 8182 "reply=pong" "READY socat" "PEER 10.9.0.1"
listen nc tcp 8183 && fallback nc-tcp connect 8183 "rc=0" "READY nc"

if [ "$fails" -gt 0 ]; then
	echo "e2e: $fails scenario(s) failed"
	exit 1
fi
echo "e2e: all passed"
