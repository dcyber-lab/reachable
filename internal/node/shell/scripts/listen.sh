# listen.sh PROTO PORT SECONDS FAMILY -- wait for one TCP connection or one
# UDP probe datagram on PORT. PROTO is tcp or udp, FAMILY 4 or 6.
# Prints PID <pid> first, then one of: INUSE, ERR <why>, READY <tool>; after READY one of
# PEER <addr> (addr is "?" when the tool can't tell), NOCONN.
# UDP probes are answered with "pong" so the sender can check the way back.
main() {
	export LC_ALL=C PATH="$PATH:/usr/sbin:/sbin"
	echo "PID $$" # for kill.sh
	proto=$1 port=$2 secs=$3 fam=$4
	if command -v ss >/dev/null 2>&1; then
		flag=-Hltn
		[ "$proto" = udp ] && flag=-Hlun
		if [ -n "$(ss "$flag" "sport = :$port" 2>/dev/null)" ]; then
			echo INUSE; return 0
		fi
	fi
	if command -v python3 >/dev/null 2>&1; then
		python3 - "$proto" "$port" "$secs" <<'PY'
import errno, socket, sys, time
proto, port, secs = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
kind = socket.SOCK_DGRAM if proto == "udp" else socket.SOCK_STREAM
def bind():
    # Dual-stack first, so one socket serves v4 and v6 probes.
    try:
        s = socket.socket(socket.AF_INET6, kind)
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("::", port))
        return s
    except OSError as e:
        if e.errno in (errno.EADDRINUSE, errno.EACCES):
            raise
    s = socket.socket(socket.AF_INET, kind)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    return s
def peer(addr):
    p = addr[0]
    return p[7:] if p.startswith("::ffff:") else p
try:
    s = bind()
except OSError as e:
    print("INUSE" if e.errno == errno.EADDRINUSE else "ERR " + e.strerror, flush=True)
    sys.exit(0)
print("READY python3", flush=True)
deadline = time.time() + secs
try:
    if kind == socket.SOCK_STREAM:
        s.listen(1)
        s.settimeout(secs)
        c, addr = s.accept()
        print("PEER " + peer(addr), flush=True)
        c.close()
    else:
        # Keep answering until the deadline instead of stopping at the first
        # probe: once the port closes, the sender's retries would draw ICMP
        # port-unreachable and look like a REJECT rule.
        seen = False
        while time.time() < deadline:
            s.settimeout(max(deadline - time.time(), 0.01))
            try:
                data, addr = s.recvfrom(2048)
            except socket.timeout:
                break
            if not data.startswith(b"reachable-probe"):
                continue
            if not seen:
                print("PEER " + peer(addr), flush=True)
                seen = True
            try:
                s.sendto(b"pong\n", addr)
            except OSError:
                pass  # a local firewall on the way out; the sender will notice
        if not seen:
            print("NOCONN", flush=True)
except socket.timeout:
    print("NOCONN", flush=True)
PY
		return 0
	fi
	if command -v socat >/dev/null 2>&1; then
		if [ "$proto" = udp ]; then
			addr="UDP$fam-RECVFROM:$port,reuseaddr"
		else
			addr="TCP$fam-LISTEN:$port,reuseaddr"
		fi
		timeout "$secs" socat -T1 "$addr" SYSTEM:'echo PEER $SOCAT_PEERADDR >&2; echo pong' 2>&1 </dev/null &
		pid=$!
		tool=socat
	elif [ "$proto" = tcp ] && command -v nc >/dev/null 2>&1; then
		six=
		[ "$fam" = 6 ] && six=-6
		(
			timeout "$secs" nc $six -l "$port"
			r=$?
			# 124 is a real timeout; anything else is probably the wrong dialect.
			[ "$r" = 0 ] || [ "$r" = 124 ] && exit "$r"
			timeout "$secs" nc $six -l -p "$port"
		) >/dev/null 2>&1 </dev/null &
		pid=$!
		tool=nc
	else
		echo "ERR no python3 or socat (or nc, for tcp) to listen with"; return 0
	fi
	sleep 0.3
	kill -0 "$pid" 2>/dev/null || { echo "ERR $tool could not listen on $proto/$port"; return 0; }
	echo "READY $tool"
	wait "$pid"
	rc=$?
	if [ "$rc" = 124 ]; then echo NOCONN; elif [ "$tool" = nc ]; then echo "PEER ?"; fi
}
main "$@" </dev/null
