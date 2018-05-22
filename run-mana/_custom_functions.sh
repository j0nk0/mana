#!/bin/bash
ARCH="uname -m"

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

