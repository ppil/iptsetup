#!/bin/sh
# iptables setup script
# Written by Peter Pilarski for EMUSec competitions
# Based on rules from https://serverfault.com/questions/245711/iptables-tips-tricks/245713

version="1.3"

usage() {
	echo "Quick iptables setup script v$version

-p <port[:port]>
	Ban-hammer port. If a connection is made to a matching port, then 
	that IP will be	banned for 3 days (or until reboot). This ban will
	be in the raw table and will take priority over most other rules.
	Takes a TCP port or range (e.g.: 20:23).
	Default: 139
-b <file>
	IP blacklist, newline separated. These IPs will be dropped.
	Default: ./blacklist
-w <file>
	IP whitelist, newline separated. These IPs will be allowed in the
	raw table, taking priority over most other rules.
	Default: ./whitelist
-t <file>
	TCP port accept list, newline separated.
	Default: ./tcp_ports
-u <file>
	UDP port accept list, newline separeted.
	Default: ./udp_ports
-s
	Drop potential shellshock attempts.
	Warning: Will probably cause problems transferring shell scripts.
-c
	Clear bans (AKA Kenny Loggins mode).
	Will not restore bans after applying new rules.
-h
	For when you miss reading this.
"
}
parseOpts() {
	while getopts :hHsScCp:P:b:B:w:W:t:T:u:U: opt; do
		case $opt in
			p|P) # Ban-hammer port
				banPort="$OPTARG"
				;;
			c|C) # Clear bans
				clearBans=1
				;;
			b|B) # IP blacklist
				blackIPs="$OPTARG"
				;;
			w|W) # IP whitelist
				whiteIPs="$OPTARG"
				;;
			s|S) # anti-shellshock
				shocker=1
				;;
			t|T) # TCP port whitelist
				tcpPorts="$OPTARG"
				;;
			u|U) # UDP port witelist
				udpPorts="$OPTARG"
				;;
			h|H) # Help
				usage
				exit 0
				;;
			\?) # Unknown/invalid
				echo "Invalid option: -$OPTARG"
				usage
				exit 1
				;;
			:) # Missing arg
				echo "An argument must be specified for -$OPTARG"
				usage
				exit 1
				;;	
		esac
	done
}
first() {
	# Save current bans before flushing raw table
	[ "$clearBans" ] || cat /proc/net/xt_recent/banned 2>/dev/null | cut -d" " -f1 | cut -d= -f2 > ./banned_IPs_save.tmp
	# Flush current tables
	iptables -F
	iptables -F -t raw
	# Allow loopback
	iptables -A INPUT -i lo -j ACCEPT
	# Allow established connections
	iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
	# Allow ICMP echo (required for ISTS)
	iptables -A INPUT -p icmp --icmp-type 8 -j ACCEPT
}
bwList() { # Whitelist/blacklist IPs
	if [ -e "$whiteIPs" ]; then
		while read wIP; do
			echo "Allowing $wIP"
			iptables -t raw -A PREROUTING -s $wIP -j ACCEPT
		done < "$whiteIPs"
	fi
	if [ -e "$blackIPs" ]; then
		while read bIP; do
			echo "Blocking $bIP"
			iptables -A INPUT -t filter -s $bIP -j DROP
		done < "$blackIPs"
	fi
}
allowPorts() {
	# Allow TCP port list
	if [ -e "$tcpPorts" ]; then
		while read port; do
			echo "Allowing TCP port $port."
			iptables -A INPUT -t filter -p tcp --dport $port -j ACCEPT
		done < "$tcpPorts"
	fi
	# Allow UDP port list
	if [ -e "$udpPorts" ]; then
		while read port; do
			echo "Allowing UDP port $port."
			iptables -A INPUT -t filter -p udp --dport $port -j ACCEPT
		done < "$udpPorts"
	fi
}
banPort() { # Fuck this port in particular. Say goodbye to any hosts that hit it up.
	
	# Drop anything in this list for 3 days
	# Raw table prerouting gets priority, other rules be damned.
	iptables -t raw -A PREROUTING -m recent --name banned --rcheck --seconds 259200 -j DROP
	# Log the event, add the IP to this list
	iptables -t raw -A PREROUTING -p tcp --dport $banPort -m recent --name banned --set -j LOG --log-prefix "Banned:"
	iptables -t raw -A PREROUTING -p tcp --dport $banPort -m recent --name banned --set -j DROP
	echo "Remind the team not to touch TCP $banPort"
	
	# Notes: Rules for the raw table need to be deleted explicitly ('iptables -F -t raw')
	#		 Use `echo / > /proc/net/xt_recent/banned` to clear the ban list without flushing the table.
	#		 Individual IPs can be unbanned with `echo -1.2.3.4 > /proc/net/xt_recent/banned` (use +1.2.3.4 to add to list). 
	# 		 View current bans with `cat /proc/net/xt_recent/banned | cut -d" " -f1 | cut -d= -f2`
}
dropScans() { # Drops packets for various TCP scans.
	# SYN-FIN
	iptables -t raw -A PREROUTING -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
	# SYN-RST
	iptables -t raw -A PREROUTING -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
	# X-mas
	iptables -t raw -A PREROUTING -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,PSH,URG -j DROP
	# FIN
	iptables -t raw -A PREROUTING -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN -j DROP
	# NULL
	iptables -t raw -A PREROUTING -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
}
others() {
	# Drop shellshock attempts (packet contains "() {")
	[ "$shocker" ] && iptables -A INPUT -m string --algo bm --hex-string '|28 29 20 7B|' -j DROP
	# Drop invalid packets (not associated with a known connection)
	iptables -A INPUT -m state --state INVALID -j DROP
	iptables -A FORWARD -m state --state INVALID -j DROP
	iptables -A OUTPUT -m state --state INVALID -j DROP
	# Default drop rule
	iptables -A INPUT -j DROP
}
restoreBans() {
	if [ -e "./banned_IPs_save.tmp" ]; then
		while read ip; do
			echo "Re-banning $ip"
			echo "+$ip" > /proc/net/xt_recent/banned
		done < ./banned_IPs_save.tmp
		rm -f ./banned_IPs_save.tmp
	fi
}

# Set defaults
tcpPorts="./tcp_ports"
udpPorts="./udp_ports"
whiteIPs="./whitelist"
blackIPs="./blacklist"
banPort=139 # Can be a range (banPort=20:23)

# Get options
parseOpts "$@"

# Got root?
if [ "$(whoami)" != "root" ]; then 
	echo "This script needs to be run as root."
	exit 1
fi
# Got iptables?
if [ ! -e "$(which iptables 2>/dev/null)" ]; then
	echo "ERROR: Iptables isn't even installed..."
	exit 1
fi

first # Flush rules, add priority accepts
bwList # IP black/white lists
allowPorts # Allowed TCP/UDP ports
banPort # Fuck-off port
dropScans # Drop some TCP port scans.
others # Final touches, default drop
[ "$clearBans" ] || restoreBans # Restore previously banned IPs
