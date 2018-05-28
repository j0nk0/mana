#!/bin/bash
etc=/etc/mana-toolkit
lib=/usr/lib/mana-toolkit
loot=/var/lib/mana-toolkit
share=/usr/share/mana-toolkit

function killem() {
	service apache2 stop

	pkill dhcpd
	pkill dnsmasq
	pkill dnsspoof
	pkill dns2proxy
	pkill hostapd
	pkill msfconsole
#	pkill python
#	pkill ruby
	pkill stunnel4
	pkill sslstrip
	pkill sslsplit
	pkill tinyproxy

#	rm $EXNODE
	rm /tmp/crackapd.run

	iptables --policy INPUT ACCEPT
	iptables --policy FORWARD ACCEPT
	iptables --policy OUTPUT ACCEPT
	iptables -t nat -F
}
killem
