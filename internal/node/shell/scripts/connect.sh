# connect.sh IP PORT SECONDS -- open a TCP connection with bash's /dev/tcp.
# Prints rc= (124 means timed out), ms= and the last error line.
main() {
	export LC_ALL=C
	command -v timeout >/dev/null 2>&1 || { echo "rc=127"; echo "err=no timeout(1) on this host"; return 0; }
	start=$(date +%s%N)
	err=$(timeout "$3" bash -c 'exec 3<>"/dev/tcp/$0/$1"' "$1" "$2" 2>&1)
	rc=$?
	end=$(date +%s%N)
	echo "rc=$rc"
	echo "ms=$(( (end - start) / 1000000 ))"
	echo "err=$(printf '%s' "$err" | tail -n1)"
}
main "$@" </dev/null
