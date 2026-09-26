# ping.sh IP COUNT -- raw ping output; the caller parses it.
main() {
	export LC_ALL=C PATH="$PATH:/usr/sbin:/sbin"
	ping -n -c "$2" -i 0.2 -W 1 "$1" 2>&1
}
main "$@" </dev/null
