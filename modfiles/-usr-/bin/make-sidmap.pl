#!/usr/bin/perl -w

system('/var/smoothwall/mods/GAR/usr/bin/smoothwall/create-sidmap.pl /var/smoothwall/snort/rules >/var/smoothwall/snort/rules/sid-msg.map');
system('/bin/chown nobody:nobody /var/smoothwall/snort/rules/sid-msg.map');
