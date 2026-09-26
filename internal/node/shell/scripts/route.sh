# route.sh IP -- which interface, source address and gateway this host
# would use to reach IP, plus that interface's MTU.
main() {
	export LC_ALL=C PATH="$PATH:/usr/sbin:/sbin"
	out=$(ip route get "$1" 2>&1) || { echo "err=$out"; return 0; }
	echo "route=$(echo "$out" | head -n1)"
	dev=$(echo "$out" | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -n1)
	[ -n "$dev" ] && echo "mtu=$(cat "/sys/class/net/$dev/mtu" 2>/dev/null)"
}
main "$@" </dev/null
