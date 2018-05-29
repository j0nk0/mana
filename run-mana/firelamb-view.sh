#!/bin/sh

etc=/etc/mana-toolkit
lib=/usr/lib/mana-toolkit
share=/usr/share/mana-toolkit
loot=/var/lib/mana-toolkit

$share/firelamb/firelamb.py -l -t $loot/sslsplit/
