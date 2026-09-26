#!/usr/bin/env bash
# lab.sh up|down DIR -- two "servers" as network namespaces, each running
# sshd, for the end-to-end tests. Needs root.
#
#   root ns --10.8.1.0/24-- ha --10.9.0.0/24, fd00:9::/64-- hb --10.8.2.0/24-- root ns
#            (mgmt: we ssh in here)      (data link A <-> B)
#
# Everything lives in DIR: keys, sshd configs and an ssh_config with hosts
# "ha" and "hb", used as `reachable -ssh "-F DIR/ssh_config" ha hb`.
set -euo pipefail

down() {
	for n in ha hb; do
		[ -f "$dir/sshd-$n.pid" ] && kill "$(cat "$dir/sshd-$n.pid")" 2>/dev/null || true
		ip netns del "$n" 2>/dev/null || true
	done
	ip link del r-a 2>/dev/null || true
	ip link del r-b 2>/dev/null || true
	rm -rf /etc/netns/ha /etc/netns/hb
}

up() {
	down
	mkdir -p "$dir" /run/sshd
	for n in ha hb; do
		ip netns add "$n"
		ip -n "$n" link set lo up
	done
	ip link add r-a type veth peer name mgmt netns ha
	ip link add r-b type veth peer name mgmt netns hb
	ip addr add 10.8.1.1/24 dev r-a && ip link set r-a up
	ip addr add 10.8.2.1/24 dev r-b && ip link set r-b up
	ip -n ha addr add 10.8.1.2/24 dev mgmt && ip -n ha link set mgmt up
	ip -n hb addr add 10.8.2.2/24 dev mgmt && ip -n hb link set mgmt up

	ip link add dA netns ha type veth peer name dB netns hb
	ip -n ha addr add 10.9.0.1/24 dev dA
	ip -n hb addr add 10.9.0.2/24 dev dB
	if [ -d /proc/sys/net/ipv6 ]; then
		ip -n ha -6 addr add fd00:9::1/64 dev dA nodad
		ip -n hb -6 addr add fd00:9::2/64 dev dB nodad
	fi
	ip -n ha link set dA up
	ip -n hb link set dB up

	# A resolves hb.lab to B's data address (ip netns exec bind-mounts this
	# over /etc/hosts for everything started in ha, sshd included).
	mkdir -p /etc/netns/ha
	{ cat /etc/hosts; echo "10.9.0.2 hb.lab"; } >/etc/netns/ha/hosts

	rm -f "$dir/id" "$dir/id.pub" "$dir/hostkey" "$dir/hostkey.pub"
	ssh-keygen -q -t ed25519 -N '' -f "$dir/id"
	ssh-keygen -q -t ed25519 -N '' -f "$dir/hostkey"
	cp "$dir/id.pub" "$dir/authorized_keys"
	chmod 600 "$dir/authorized_keys"
	for n in ha hb; do
		ip netns exec "$n" "$(command -v sshd)" -f /dev/null \
			-o HostKey="$dir/hostkey" \
			-o AuthorizedKeysFile="$dir/authorized_keys" \
			-o StrictModes=no \
			-o PermitRootLogin=prohibit-password \
			-o PasswordAuthentication=no \
			-o PidFile="$dir/sshd-$n.pid"
	done
	cat >"$dir/ssh_config" <<CFG
Host ha
  HostName 10.8.1.2
Host hb
  HostName 10.8.2.2
Host *
  User root
  IdentityFile $dir/id
  IdentitiesOnly yes
  StrictHostKeyChecking no
  UserKnownHostsFile /dev/null
  LogLevel ERROR
CFG
	for n in ha hb; do
		for _ in $(seq 50); do
			ssh -F "$dir/ssh_config" -o BatchMode=yes "$n" true 2>/dev/null && continue 2
			sleep 0.1
		done
		echo "lab: sshd in $n never came up" >&2
		exit 1
	done
}

[ $# -eq 2 ] || { echo "usage: $0 up|down DIR" >&2; exit 2; }
dir=$2
case $1 in
up) up ;;
down) down ;;
*) echo "usage: $0 up|down DIR" >&2; exit 2 ;;
esac
