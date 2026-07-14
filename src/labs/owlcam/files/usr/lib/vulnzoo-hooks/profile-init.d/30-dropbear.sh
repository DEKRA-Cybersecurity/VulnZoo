#!/bin/sh

service dropbear stop

uci set dropbear.@dropbear[0].BannerFile='/etc/banner.ssh'
uci commit dropbear

service dropbear restart