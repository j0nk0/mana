#!/bin/bash
ARCH="uname -m"
TERM_="xterm"

#################################### < Resolution > ####################################
#fluxion_3.1/fluxion.sh
function fluxion_set_resolution() { # Windows + Resolution

  # Calc options
  RATIO=4

  # Get demensions
  SCREEN_SIZE=$(xdpyinfo | grep dimension | awk '{print $4}' | tr -d "(")
  SCREEN_SIZE_X=$(printf '%.*f\n' 0 $(echo $SCREEN_SIZE | sed -e s'/x/ /'g | awk '{print $1}'))
  SCREEN_SIZE_Y=$(printf '%.*f\n' 0 $(echo $SCREEN_SIZE | sed -e s'/x/ /'g | awk '{print $2}'))

  PROPOTION=$(echo $(awk "BEGIN {print $SCREEN_SIZE_X/$SCREEN_SIZE_Y}")/1 | bc)
  NEW_SCREEN_SIZE_X=$(echo $(awk "BEGIN {print $SCREEN_SIZE_X/$RATIO}")/1 | bc)
  NEW_SCREEN_SIZE_Y=$(echo $(awk "BEGIN {print $SCREEN_SIZE_Y/$RATIO}")/1 | bc)

  NEW_SCREEN_SIZE_BIG_X=$(echo $(awk "BEGIN {print 1.5*$SCREEN_SIZE_X/$RATIO}")/1 | bc)
  NEW_SCREEN_SIZE_BIG_Y=$(echo $(awk "BEGIN {print 1.5*$SCREEN_SIZE_Y/$RATIO}")/1 | bc)

  SCREEN_SIZE_MID_X=$(echo $(($SCREEN_SIZE_X + ($SCREEN_SIZE_X - 2 * $NEW_SCREEN_SIZE_X) / 2)))
  SCREEN_SIZE_MID_Y=$(echo $(($SCREEN_SIZE_Y + ($SCREEN_SIZE_Y - 2 * $NEW_SCREEN_SIZE_Y) / 2)))

  # Upper
  TOPLEFT="-geometry $NEW_SCREEN_SIZE_Xx$NEW_SCREEN_SIZE_Y+0+0"
  TOPRIGHT="-geometry $NEW_SCREEN_SIZE_Xx$NEW_SCREEN_SIZE_Y-0+0"
  TOP="-geometry $NEW_SCREEN_SIZE_Xx$NEW_SCREEN_SIZE_Y+$SCREEN_SIZE_MID_X+0"

  # Lower
  BOTTOMLEFT="-geometry $NEW_SCREEN_SIZE_Xx$NEW_SCREEN_SIZE_Y+0-0"
  BOTTOMRIGHT="-geometry $NEW_SCREEN_SIZE_Xx$NEW_SCREEN_SIZE_Y-0-0"
  BOTTOM="-geometry $NEW_SCREEN_SIZE_Xx$NEW_SCREEN_SIZE_Y+$SCREEN_SIZE_MID_X-0"

  # Y mid
  LEFT="-geometry $NEW_SCREEN_SIZE_Xx$NEW_SCREEN_SIZE_Y+0-$SCREEN_SIZE_MID_Y"
  RIGHT="-geometry $NEW_SCREEN_SIZE_Xx$NEW_SCREEN_SIZE_Y-0+$SCREEN_SIZE_MID_Y"

  # Big
  TOPLEFTBIG="-geometry $NEW_SCREEN_SIZE_BIG_Xx$NEW_SCREEN_SIZE_BIG_Y+0+0"
  TOPRIGHTBIG="-geometry $NEW_SCREEN_SIZE_BIG_Xx$NEW_SCREEN_SIZE_BIG_Y-0+0"
}

detect_arch(){
        if $ARCH | grep -i "arm" > /dev/null; then
         distro="arm"
         is_arm=1
        elif $ARCH | grep -i "x86_64" > /dev/null; then
         distro="x86_64"
         is_arm=0
        elif $ARCH | grep -i "x86" > /dev/null; then
         distro="x86"
         is_arm=0
        fi
        if [ -z $distro ] ; then
         echo "Error! Cannot detect arch! Assuming arch is: x86"
         distro="x86"
         is_arm=0
        fi
}

 fluxion_set_resolution
 detect_arch

  if [ $is_arm -eq 1 ] ; then
   hostapd=$(cd $(dirname $0); pwd -P)/../hostapd-2.3/hostapd/hostapd-2.3_rpi_arm_kali #Default:[/usr/lib/mana-toolkit/hostapd]
  else
   hostapd=$(cd $(dirname $0); pwd -P)/../hostapd-2.3/hostapd/hostapd-2.3_x86_x86_kali #Default:[/usr/lib/mana-toolkit/hostapd]
  fi
