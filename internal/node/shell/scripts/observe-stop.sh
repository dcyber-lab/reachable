# observe-stop.sh DIR BASELINE -- end an observation started by
# observe-start.sh and report what it saw:
#   window=BASELINE PROBE         seconds each counter window lasted
#   ctr=KIND<TAB>SCOPE<TAB>NAME<TAB>BASELINE-DELTA<TAB>PROBE-DELTA
#                                 every counter that moved while we probed
#   pkt=LINE                      tcpdump lines about our port
#   drop=SRC SPORT DST DPORT LOCATION REASON NETNS   kernel drops of our
#                                 packets; NETNS is "here", or "other" for
#                                 another network namespace (a container)
main() {
	export LC_ALL=C PATH="$PATH:/usr/sbin:/sbin"
	dir=$1 base=$2
	as_root || { echo "err=needs root or passwordless sudo"; return 0; }
	case $dir in /tmp/reachable-obs.*) ;; *) echo "err=not an observation: $dir"; return 0 ;; esac
	[ -d "$dir" ] || { echo "err=observation $dir is gone"; return 0; }

	snap "$dir/s2"
	echo "window=$base $(( $(date +%s) - $(cat "$dir/t1" 2>/dev/null || date +%s) ))"
	# Let the last packets land in the capture and the trace, then stop both.
	sleep 0.5
	for p in $(cat "$dir/pids"); do $SUDO kill "$p" 2>/dev/null; done
	sleep 0.3

	awk -F '\t' '
		FILENAME == ARGV[1] { s0[$1 FS $2 FS $3] = $4; next }
		FILENAME == ARGV[2] { s1[$1 FS $2 FS $3] = $4; next }
		{
			k = $1 FS $2 FS $3
			if (!(k in s1)) next
			# Of the protocol statistics only the ones about losing packets;
			# the rest move with any traffic, our own ssh session included.
			if ($1 == "stat" && $3 !~ /Drop|Discard|Filter|Overflow|Err|Fail|PAWS|NoRoute|NoPorts|Invalid|Prune|Unknown|Bad|Rej|Backlog|Full|Truncated/) next
			d = $4 - s1[k]
			b = (k in s0) ? s1[k] - s0[k] : 0
			if (d > 0) print "ctr=" k "\t" (b > 0 ? b : 0) "\t" d
		}' "$dir/s0" "$dir/s1" "$dir/s2"

	sed -n '/./s/^/pkt=/p' "$dir/cap" 2>/dev/null

	if [ -s "$dir/drops" ]; then
		t=$(tracefs)
		{
			[ -n "$t" ] && $SUDO cat "$t/events/skb/kfree_skb/format" 2>/dev/null |
				grep -oE '\{ [0-9]+, "[A-Z0-9_]+" \}' | tr -d '{},"' | awk '{ print "R", $1, $2 }'
			grep '^DROP ' "$dir/drops"
		} | awk -v me="$(cat "$dir/netns" 2>/dev/null)" '
			$1 == "R" { name[$2] = $3; next }
			{
				r = ($7 in name) ? name[$7] : ($7 == 0 ? "-" : $7)
				ns = ($8 == 0 || me == "" || $8 == me) ? "here" : "other"
				print "drop=" $2, $3, $4, $5, $6, r, ns
			}'
	fi
	rm -rf "$dir"
}
main "$@" </dev/null
