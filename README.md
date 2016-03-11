# iptables setup script

By default, this script will:
  - Flush iptables
  - Allow all loopback connections
  - Allow packets for, or related to, established connections
  - Allow ICMP Echoes (ISTS12 requirement)
  - Ban any hosts that try TCP port 139 (for 3 days)
  - Drop any packets that looks like a port scan (X-mas, SYN-RST, SYN-FIN, FIN, NULL)
  - Drop any packets with an invalid state
  - Drop everything that's not explicitly allowed.

Tested on CentOS, Debian, Gentoo, Arch, openSUSE, Slackware.