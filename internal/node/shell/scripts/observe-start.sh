# observe-start.sh PROTO PORT LIFETIME BASELINE -- start watching this
# machine for packets to or from PORT: what hooks could drop them, a packet
# capture, a trace of the kernel freeing them, and counter snapshots.
#
# Takes snapshot s0, starts the capture and the trace (both killed by
# observe-stop.sh, or by themselves after LIFETIME seconds), waits BASELINE
# seconds with nothing sent and takes s1: the counters' background rate, to
# tell our probes apart from traffic on a busy machine. Prints:
#   err=...                 can't observe at all (not root)
#   dir=DIR                 hand this to observe-stop.sh
#   kernel=, hook=, rpf=, fw=, ct=, sysctl=   what could drop packets here
#   have=WHAT / missing=WHAT: why        which observations are running
main() {
	export LC_ALL=C PATH="$PATH:/usr/sbin:/sbin"
	proto=$1 port=$2 life=$3 base=$4
	as_root || { echo "err=needs root or passwordless sudo"; return 0; }
	dir=$(mktemp -d /tmp/reachable-obs.XXXXXX) || { echo "err=mktemp failed"; return 0; }
	echo "dir=$dir"
	echo "kernel=$(uname -r)"
	stat -L -c %i /proc/self/ns/net >"$dir/netns" 2>/dev/null
	inventory
	snap "$dir/s0"
	uptime_now >"$dir/t0"
	: >"$dir/pids"

	if command -v tcpdump >/dev/null 2>&1; then
		# The ICMP clauses catch unreachables about our port: a REJECT
		# answered by a router or firewall on the way.
		filter="$proto port $port or (icmp and icmp[0] == 3 and icmp[30:2] == $port) or (icmp6 and ip6[40] == 1 and ip6[90:2] == $port)"
		$SUDO timeout "$life" tcpdump -l -nn -tt -i any -s 160 -c 2000 "$filter" >"$dir/cap" 2>"$dir/cap.err" </dev/null &
		echo $! >>"$dir/pids"
		wait_for "$dir/cap.err" "listening on" $! && echo "have=capture" ||
			echo "missing=capture: tcpdump did not start: $(head -n1 "$dir/cap.err")"
	else
		echo "missing=capture: no tcpdump"
	fi

	droptrace

	sleep "$base"
	snap "$dir/s1"
	uptime_now >"$dir/t1"
	echo "ready=1"
}

# wait_for FILE TEXT PID -- up to 15s for TEXT to show up in FILE, giving
# up as soon as PID (the process writing it) has died.
wait_for() {
	for _ in $(seq 150); do
		grep -q "$2" "$1" 2>/dev/null && return 0
		$SUDO kill -0 "$3" 2>/dev/null || { grep -q "$2" "$1" 2>/dev/null; return; }
		sleep 0.1
	done
	return 1
}

# droptrace starts bpftrace on skb:kfree_skb, filtered to our port: where
# in the kernel each of our packets was dropped, and why (5.17+).
droptrace() {
	command -v bpftrace >/dev/null 2>&1 || { echo "missing=droptrace: no bpftrace"; return; }
	[ -r /sys/kernel/btf/vmlinux ] || { echo "missing=droptrace: kernel has no BTF"; return; }
	t=$(tracefs) || { echo "missing=droptrace: no skb:kfree_skb tracepoint (tracefs not mounted?)"; return; }
	reason=0
	$SUDO grep -q 'field:.* reason;' "$t/events/skb/kfree_skb/format" && reason='args->reason'
	num=6
	[ "$proto" = udp ] && num=17
	# Raw header bytes rather than struct bitfields, which older bpftrace
	# can't read.
	cat >"$dir/drops.bt" <<EOF
tracepoint:skb:kfree_skb
{
	\$skb = (struct sk_buff *)args->skbaddr;
	\$p = \$skb->head + \$skb->network_header;
	// The tracepoint fires for every network namespace on the machine
	// (containers too): note which one, to tell ours from the rest.
	\$ns = (uint64)0;
	if (\$skb->dev != 0) { \$ns = \$skb->dev->nd_net.net->ns.inum; }
	else if (\$skb->sk != 0) { \$ns = \$skb->sk->__sk_common.skc_net.net->ns.inum; }
	\$v = *(uint8 *)\$p >> 4;
	if (\$v == 4 && *(uint8 *)(\$p + 9) == $num) {
		\$t = \$p + (*(uint8 *)\$p & 0xf) * 4;
		\$sp = (*(uint8 *)\$t << 8) | *(uint8 *)(\$t + 1);
		\$dp = (*(uint8 *)(\$t + 2) << 8) | *(uint8 *)(\$t + 3);
		if (\$sp == $port || \$dp == $port) {
			printf("DROP %s %d %s %d %s %d %u\n", ntop(*(uint32 *)(\$p + 12)), \$sp, ntop(*(uint32 *)(\$p + 16)), \$dp, ksym(args->location), $reason, \$ns);
		}
	}
	if (\$v == 6 && *(uint8 *)(\$p + 6) == $num) {
		\$t = \$p + 40;
		\$sp = (*(uint8 *)\$t << 8) | *(uint8 *)(\$t + 1);
		\$dp = (*(uint8 *)(\$t + 2) << 8) | *(uint8 *)(\$t + 3);
		if (\$sp == $port || \$dp == $port) {
			printf("DROP %s %d %s %d %s %d %u\n", ntop(((struct ipv6hdr *)\$p)->saddr.in6_u.u6_addr8), \$sp, ntop(((struct ipv6hdr *)\$p)->daddr.in6_u.u6_addr8), \$dp, ksym(args->location), $reason, \$ns);
		}
	}
}
EOF
	$SUDO timeout "$life" bpftrace "$dir/drops.bt" >"$dir/drops" 2>"$dir/drops.err" </dev/null &
	echo $! >>"$dir/pids"
	if wait_for "$dir/drops" "Attaching" $!; then
		echo "have=droptrace"
	else
		echo "missing=droptrace: bpftrace did not start: $(grep -v RLIMIT "$dir/drops.err" | head -n1)"
	fi
}

# inventory prints what on this machine could drop a packet.
inventory() {
	ip -o -d link show 2>/dev/null | awk '
		/prog\/xdp/ {
			dev = $2; sub(/@.*/, "", dev); sub(/:$/, "", dev)
			mode = "native"
			if ($0 ~ /xdpgeneric/) mode = "generic"; else if ($0 ~ /xdpoffload/) mode = "offload"
			id = $0; sub(/.*prog\/xdp id /, "", id); sub(/ .*/, "", id)
			print "hook=xdp\t" dev "\t" mode " id " id
		}'
	# clsact / ingress qdiscs are where tc programs hang (4.5+); tcx (6.6+)
	# has no qdisc and only shows up in bpftool.
	for d in $(tc qdisc show 2>/dev/null | awk '$2 == "clsact" || $2 == "ingress" { for (i = 1; i <= NF; i++) if ($i == "dev") print $(i + 1) }' | sort -u); do
		for way in ingress egress; do
			tc filter show dev "$d" "$way" 2>/dev/null | awk -v d="$d" -v w="$way" '
				/^filter/ && / handle / {
					what = ($0 ~ / bpf /) ? "bpf" : $5
					name = ""; if (match($0, / name [^ ]+/)) name = substr($0, RSTART + 6, RLENGTH - 6)
					id = ""; if (match($0, / id [0-9]+/)) id = substr($0, RSTART + 1, RLENGTH - 1)
					print "hook=tc-" w "\t" d "\t" what (name != "" ? " " name : "") (id != "" ? " " id : "")
				}'
		done
	done
	if command -v bpftool >/dev/null 2>&1; then
		$SUDO bpftool net show 2>/dev/null | awk '/tcx\/(ingress|egress)/ { dev = $1; sub(/\(.*/, "", dev); split($2, w, "/"); print "hook=tcx-" w[2] "\t" dev "\t" $3 " " $4 " " $5 }'
		$SUDO bpftool cgroup tree 2>/dev/null | awk '$2 ~ /^cgroup_(inet|sock|device)|^(ingress|egress|connect|bind|sendmsg|recvmsg|sock_ops)/ { n[$2]++ }
			END { for (t in n) print "hook=cgroup\t" t "\t" n[t] " program(s)" }'
	else
		echo "missing=inventory: no bpftool, so tcx and cgroup eBPF programs are not listed"
	fi
	for f in /proc/sys/net/ipv4/conf/*/rp_filter; do
		v=$(cat "$f" 2>/dev/null)
		[ -n "$v" ] && [ "$v" != 0 ] && { d=${f%/rp_filter}; echo "rpf=${d##*/} $v"; }
	done
	c=$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null) && echo "ct=$c $(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null)"
	v=$(cat /proc/sys/net/ipv4/tcp_tw_recycle 2>/dev/null) && [ "$v" != 0 ] && echo "sysctl=net.ipv4.tcp_tw_recycle=$v"
	for save in iptables-save ip6tables-save; do
		command -v "$save" >/dev/null 2>&1 &&
			$SUDO "$save" 2>/dev/null | awk -v s="$save" '/^\*/ { t = substr($0, 2) } /^:/ && $2 == "DROP" { print "fw=" s " " t " " substr($1, 2) " policy DROP" }'
	done
	command -v nft >/dev/null 2>&1 &&
		$SUDO nft list ruleset 2>/dev/null | awk '/^table/ { t = $2 " " $3 } /^\tchain/ { c = $2 } /policy drop/ { print "fw=nft " t " " c " policy drop" }'
}

main "$@" </dev/null
