# udp.sh IP PORT SECONDS -- send probe datagrams with bash's /dev/udp and
# wait for the listener's "pong". Prints sent=0|1, reply=pong|none, err=.
main() {
	export LC_ALL=C
	if ! exec 3<>"/dev/udp/$1/$2"; then
		echo "sent=0"; echo "reply=none"; echo "err=could not open a UDP socket"; return 0
	fi 2>/dev/null
	err='' reply=''
	# bash's read takes a socket one byte per read(2), which on UDP throws
	# away the rest of the datagram; dd reads the whole datagram at once.
	# An ICMP port-unreachable for an earlier datagram surfaces as
	# ECONNREFUSED on whichever socket call comes next, often this read.
	recv() {
		out=$(timeout "$1" dd bs=512 count=1 <&3 2>&1)
		case $out in
		*pong*) reply=pong ;;
		*refused*) err="Connection refused" ;;
		esac
	}
	for _ in 1 2 3; do # a few copies: UDP may lose one
		e=$( { printf 'reachable-probe\n' >&3; } 2>&1 ) || err=$e
		[ -z "$err" ] && recv 1
		[ -n "$reply$err" ] && break
	done
	[ -z "$reply$err" ] && recv "$3"
	echo "sent=1"
	echo "reply=${reply:-none}"
	echo "err=$(printf '%s' "$err" | tail -n1)"
	exec 3>&-
}
main "$@" </dev/null
