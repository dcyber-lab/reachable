# trace.sh IP -- hop list, from whichever tracer exists.
main() {
	export LC_ALL=C PATH="$PATH:/usr/sbin:/sbin"
	if command -v tracepath >/dev/null 2>&1; then
		timeout 15 tracepath -n -m 15 "$1" 2>&1
	elif command -v traceroute >/dev/null 2>&1; then
		timeout 15 traceroute -n -q 1 -w 1 -m 15 "$1" 2>&1
	else
		echo "no tracepath or traceroute on this host"
	fi
}
main "$@" </dev/null
