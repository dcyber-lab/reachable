# kill.sh PID -- stop PID and every process under it. Not by process
# group: run locally, the script shares reachable's own group.
main() {
	export LC_ALL=C
	tree() {
		local c
		for c in $(grep -l "^PPid:[[:space:]]*$1\$" /proc/[0-9]*/status 2>/dev/null | cut -d/ -f3); do
			tree "$c"
		done
		echo "$1"
	}
	# shellcheck disable=SC2046 # one pid per word
	kill $(tree "$1") 2>/dev/null
}
main "$@" </dev/null
