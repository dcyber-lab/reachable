# iperf-server.sh PORT SECONDS -- serve exactly one iperf3 test.
main() {
	echo "PID $$" # for kill.sh
	timeout "$2" iperf3 -s -1 -p "$1" >/dev/null 2>&1 </dev/null &
	pid=$!
	sleep 0.5
	kill -0 "$pid" 2>/dev/null || { echo "ERR iperf3 could not listen on $1"; return 0; }
	echo READY
	wait "$pid"
	echo DONE
}
main "$@" </dev/null
