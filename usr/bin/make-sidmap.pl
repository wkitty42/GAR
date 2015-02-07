#!/usr/bin/perl -w

system('/var/smoothwall/mods/GAR/usr/bin/create-sidmap.pl /var/smoothwall/snort/rules 1>/var/smoothwall/snort/rules/sid-msg.map 2>/dev/nul');
system('/bin/chown nobody:nobody /var/smoothwall/snort/rules/sid-msg.map');
