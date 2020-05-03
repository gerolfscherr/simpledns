# simpledns
simple dns server

this is a really small DNS server which just can anwer simple DNS questions. it doesn't ask other dns servers, so you can use it to 'fake' responses.
it was developed to prevent a certain 'Smart'Device to 'phone home'.

no dependencies except the standard c library and libowfat

just start with ./simpledns -p 10053 -v -f configfile
will listen on all interfaces on port 10053
configfile just has key-value syntax:

github.com=1.2.3.4

dig @127.0.0.1 -p 10053 github.com -> 1.2.3.4

in order to have it run on the standard port 53 you have to run it as sudo bc port 53 is privileged:

sudo ./simpledns -v -p 53 -b 192.168.1.123 -u `id -u nobody` -g `id -u nobody`

starts simpledns on the dns standard port (listening on UDP), binding at adress 192.168.1.123 (this must be one of the ip-addresses of your computer) and sets the user id and group id to those of the user nobody

if it says 'address already in use' thats because some other process is using the port, in my case it was systemds server:
(found out with sudo lsof -i -P -n  | grep LISTEN | grep 53)
->  sudo systemctl stop systemd-resolved.service

TODO:
* less verbose

DONE:
* privilege dropping (!)
* binding to a specific interface.


