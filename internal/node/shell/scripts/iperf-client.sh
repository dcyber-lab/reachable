# iperf-client.sh IP PORT SECONDS -- iperf3 JSON report.
main() {
	timeout $(( $3 + 10 )) iperf3 -c "$1" -p "$2" -t "$3" -J 2>&1
}
main "$@" </dev/null
