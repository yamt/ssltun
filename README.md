ssltun
======

This program creates an SSL tunnel.

It's mostly same as:

	% /usr/bin/openssl s_client -connect "$1" -quiet 2>/dev/null

(I was not aware of s_client when i wrote this program. :-)
