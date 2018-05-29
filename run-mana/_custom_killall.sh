#!/bin/bash
        echo "[*] Killing...."
        service apache2 stop

        pkill -f dhcpd
        pkill -f start_dnsmasq
        pkill -f dnsspoof
        pkill -f dnsmasq
        pkill -f dns2proxy
        pkill -f firelamb
        pkill -f start_firelamb
        pkill -f hostapd
        pkill -f start_hostapd
        pkill -f start_msfconsole
        pkill -f msfconsole
        pkill -f start_msfconsole
        pkill -f start_nat_firewall
        pkill -f net-creds
#        pkill -f python
#        pkill -f ruby
        pkill -f start_netcreds
        pkill -f sslsplit
        pkill -f sslstrip
        pkill -f start_sslstrip
        pkill -f stunnel4
        pkill -f tinyproxy

        rm --verbose --force $EXNODE
        rm --verbose --force /tmp/crackapd.run

        iptables --policy INPUT ACCEPT
        iptables --policy FORWARD ACCEPT
        iptables --policy OUTPUT ACCEPT
        iptables -t nat -F
exit
