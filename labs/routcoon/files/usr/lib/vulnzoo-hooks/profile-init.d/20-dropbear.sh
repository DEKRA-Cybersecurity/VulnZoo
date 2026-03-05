#!/bin/sh

/etc/init.d/dropbear stop

uci set dropbear.@dropbear[0].PasswordAuth='on'
uci set dropbear.@dropbear[0].RootPasswordAuth='off'
# Port 22 is commonly used for SSH
uci set dropbear.@dropbear[0].Port='22'
uci set dropbear.@dropbear[0].Banner='/etc/banner'
# Enable SCP and SFTP for file transfers
uci set dropbear.@dropbear[0].enable_scp='on'
uci set dropbear.@dropbear[0].enable_sftp='on'

rm -rf /etc/dropbear/dropbear_rsa_host_key
# Generate new key wich is small enough to be cracked easily
dropbearkey -t rsa -f /etc/dropbear/dropbear_rsa_host_key -s 1024

uci commit dropbear
/etc/init.d/dropbear restart

exit 0
