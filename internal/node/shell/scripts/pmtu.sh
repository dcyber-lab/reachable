# pmtu.sh IP -- largest packet that crosses the path with DF set.
# Prints pmtu=N and how= one of:
#   iface   a full interface-MTU packet got through
#   icmp    a hop answered "fragmentation needed" with its MTU (healthy)
#   search  big packets vanished silently and we had to bisect (black hole)
# or err=.
main() {
	export LC_ALL=C PATH="$PATH:/usr/sbin:/sbin"
	ip=$1 hdr=28
	case "$ip" in *:*) hdr=48 ;; esac
	dev=$(ip route get "$ip" 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -n1)
	mtu=$(cat "/sys/class/net/$dev/mtu" 2>/dev/null || echo 1500)

	# ping waits the full -W on failure even when the kernel already knows
	# the answer, so each miss costs a second: take the MTU the error names
	# instead of bisecting whenever there is one.
	try() { out=$(ping -n -c 1 -W 1 -M "do" -s "$1" "$ip" 2>&1); }
	reported() { printf '%s' "$out" | sed -n 's/.*mtu *= *\([0-9]*\).*/\1/p' | head -n1; }

	size=$((mtu - hdr)) how=iface
	for _ in 1 2 3 4; do
		try "$size" && { echo "pmtu=$((size + hdr))"; echo "how=$how"; return 0; }
		m=$(reported)
		[ -n "$m" ] && [ $((m - hdr)) -lt "$size" ] || break
		size=$((m - hdr)) how=icmp
	done

	try 0 || { echo "err=even a minimal DF ping gets no reply"; return 0; }
	lo=0 hi=$size # invariant: lo gets through, hi does not
	while [ $((hi - lo)) -gt 1 ]; do
		mid=$(( (lo + hi) / 2 ))
		if try "$mid"; then lo=$mid; else hi=$mid; fi
	done
	echo "pmtu=$((lo + hdr))"
	echo "how=search"
}
main "$@" </dev/null
