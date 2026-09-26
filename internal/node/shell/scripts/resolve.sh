# resolve.sh NAME -- the addresses NAME resolves to here, one per line.
main() {
	export LC_ALL=C
	getent ahosts "$1" 2>/dev/null | awk '!seen[$1]++ {print $1}'
}
main "$@" </dev/null
