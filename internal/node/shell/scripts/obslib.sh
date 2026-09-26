# obslib.sh -- shared by observe-start.sh and observe-stop.sh, which get it
# prepended. Everything here only reads: no rule, sysctl or program on the
# machine is changed.

# as_root sets SUDO to "" (already root) or "sudo -n", or fails.
as_root() {
	SUDO=""
	[ "$(id -u)" = 0 ] && return 0
	if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
		SUDO="sudo -n"
		return 0
	fi
	return 1
}

# uptime_now prints seconds since boot to the hundredth: /proc/uptime works
# everywhere, where date +%N doesn't (busybox).
uptime_now() {
	cut -d' ' -f1 /proc/uptime
}

tracefs() {
	for t in /sys/kernel/tracing /sys/kernel/debug/tracing; do
		if $SUDO test -r "$t/events/skb/kfree_skb/format"; then
			echo "$t"
			return 0
		fi
	done
	return 1
}

# snap FILE -- every counter that can say a packet was dropped, normalised
# to "kind<TAB>scope<TAB>name<TAB>value" lines.
snap() {
	{
		for save in iptables-save ip6tables-save; do
			command -v "$save" >/dev/null 2>&1 || continue
			# Only DROP/REJECT rules and DROP policies: ACCEPT rules count
			# every packet of background traffic and say nothing about drops.
			$SUDO "$save" -c 2>/dev/null | awk -v fam="$save" '
				/^\*/ { table = substr($0, 2); next }
				/^:/ {
					if ($2 == "DROP") { split($3, c, /[\[:\]]/); print "fw\t" fam " " table "\tpolicy " substr($1, 2) " DROP\t" c[2] }
					next
				}
				/^\[/ && / -j (DROP|REJECT)/ {
					split($1, c, /[\[:\]]/); rule = $0; sub(/^\[[0-9]+:[0-9]+\] /, "", rule)
					n[table rule]++
					print "fw\t" fam " " table "\t" rule (n[table rule] > 1 ? " #" n[table rule] : "") "\t" c[2]
				}'
		done
		if command -v nft >/dev/null 2>&1; then
			# nftables rules only count if they have a counter; the rest are
			# left to the drop trace.
			$SUDO nft list ruleset 2>/dev/null | awk '
				/^table / { table = $2 " " $3 }
				/^\tchain / { chain = $2 }
				/counter packets [0-9]+/ && /(drop|reject)/ {
					v = $0; sub(/.*counter packets /, "", v); sub(/ .*/, "", v)
					r = $0; gsub(/counter packets [0-9]+ bytes [0-9]+/, "counter", r); gsub(/^[ \t]+/, "", r)
					print "fw\tnft " table " " chain "\t" r "\t" v
				}'
		fi
		for f in /proc/net/netstat /proc/net/snmp; do
			awk '{ if (h[$1]) { for (i = 2; i <= NF; i++) print "stat\t" substr($1, 1, length($1) - 1) "\t" k[$1, i] "\t" $i }
			       else { h[$1] = 1; for (i = 2; i <= NF; i++) k[$1, i] = $i } }' "$f" 2>/dev/null
		done
		awk '{ print "stat\tIp6\t" $1 "\t" $2 }' /proc/net/snmp6 2>/dev/null
		# Per-CPU hex columns; sum the ones that mean a drop.
		# (strtonum is gawk-only; mawk and busybox awk need this by hand.)
		awk 'function hex(s,   n, i) { n = 0; s = tolower(s); for (i = 1; i <= length(s); i++) n = n * 16 + index("0123456789abcdef", substr(s, i, 1)) - 1; return n }
		     NR == 1 { for (i = 1; i <= NF; i++) col[i] = $i; next }
		     { for (i = 1; i <= NF; i++) if (col[i] ~ /^(invalid|drop|early_drop|insert_failed)$/) s[col[i]] += hex($i) }
		     END { for (c in s) print "conntrack\tall\t" c "\t" s[c] }' /proc/net/stat/nf_conntrack 2>/dev/null
		tc -s qdisc show 2>/dev/null | awk '
			/^qdisc/ { q = $2; for (i = 1; i <= NF; i++) if ($i == "dev") d = $(i + 1) }
			/dropped/ { v = $0; sub(/.*dropped /, "", v); sub(/,.*/, "", v); print "tc\t" d "\t" q "\t" v }'
		for d in /sys/class/net/*; do
			for c in rx_dropped tx_dropped rx_missed_errors rx_fifo_errors; do
				[ -r "$d/statistics/$c" ] && printf 'nic\t%s\t%s\t%s\n' "${d##*/}" "$c" "$(cat "$d/statistics/$c")"
			done
		done
		if command -v ethtool >/dev/null 2>&1; then
			for d in /sys/class/net/*; do
				[ -e "$d/device" ] || continue # physical NICs only
				ethtool -S "${d##*/}" 2>/dev/null | awk -v d="${d##*/}" 'tolower($1) ~ /drop|xdp|miss|discard/ { sub(/:$/, "", $1); print "nic\t" d "\t" $1 "\t" $2 }'
			done
		fi
	} >"$1" 2>/dev/null
}
