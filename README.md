ssltun
======

this program creates a ssl tunnel.

it's mostly same as:

	% /usr/bin/openssl s_client -connect "$1" -quiet 2>/dev/null

(i was not aware of s_client when i wrote this program. :-)
