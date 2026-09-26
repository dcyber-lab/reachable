# Prints key=value facts about this host.
main() {
	export LC_ALL=C PATH="$PATH:/usr/sbin:/sbin"
	echo "hostname=$(hostname 2>/dev/null || uname -n)"
	echo "arch=$(uname -m)"
	echo "kernel=$(uname -r)"
	echo "user=$(id -un)"
	for t in ping ip ss python3 socat nc tracepath traceroute iperf3 getent timeout; do
		command -v "$t" >/dev/null 2>&1 && echo "tool=$t"
	done
	if command -v ip >/dev/null 2>&1; then
		ip -o addr show scope global 2>/dev/null | awk '{split($4, a, "/"); print "addr=" a[1] " " $2}'
	else
		for a in $(hostname -I 2>/dev/null); do echo "addr=$a"; done
	fi
}
main "$@" </dev/null
