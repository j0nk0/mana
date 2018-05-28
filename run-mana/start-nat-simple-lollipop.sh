#!/bin/bash
etc=/etc/mana-toolkit
lib=/usr/lib/mana-toolkit
loot=/var/lib/mana-toolkit
share=/usr/share/mana-toolkit
#start-nat-simple.sh - Will fire up MANA in NAT mode, but without any of the firelamb, sslstrip, sslsplit etc.
upstream=wlan0
phy=wlan1
conf=/sdcard/nh_files/configs/hostapd-karma.conf
hostapd=$lib/hostapd

echo '1' > /proc/sys/net/ipv4/ip_forward
rfkill unblock wlan
echo -- $phy: flushing interface --
ip addr flush dev $phy
echo -- $phy: setting ip --
ip addr add 10.0.0.1/24 dev $phy
echo -- $phy: starting the interface --
ip link set $phy up
echo -- $phy: setting route --
ip route add default via 10.0.0.1 dev $phy

# Starting AP and DHCP
sed -i "s/^interface=.*$/interface=$phy/" $conf
$hostapd $conf &
sleep 5
dnsmasq -z -C $etc/dnsmasq-dhcpd.conf -i $phy -I lo
sleep 5

# Add fking rule to table 1006
for table in $(ip rule list | awk -F"lookup" '{print $2}');
do
DEF=`ip route show table $table|grep default|grep $upstream`
if ! [ -z "$DEF" ]; then
   break
fi
done
ip route add 10.0.0.0/24 dev $phy scope link table $table

# RM quota from chains to avoid errors in iptable-save
# http://lists.netfilter.org/pipermail/netfilter-buglog/2013-October/002995.html
iptables -F bw_INPUT
iptables -F bw_OUTPUT
# Save
# iptables-save > /tmp/rules.txt
# Flush
iptables -F
iptables -F -t nat
# Masquerade
iptables -t nat -A POSTROUTING -o $upstream -j MASQUERADE
iptables -A FORWARD -i $phy -o $upstream -j ACCEPT

echo "Hit enter to kill me"
read
pkill dhcpd
pkill sslstrip
pkill sslsplit
pkill hostapd
pkill python
## Restore
#iptables-restore < /tmp/rules.txt
#rm /tmp/rules.txt
## Remove iface and routes
ip addr flush dev $phy
ip link set $phy down
