# ipt_SNATMAP and ipt_DNATMAP

Using skbmark and skbmarkmask as ipv4-address and port for SNAT/DNAT.

It is recommended to use set type "hash:ip" or "hash:ip,port".

skbmark is used as ipv4 addresses, skbmarkmask is used as port.

Тo add or remove data from a set, the ipnatset script is used which translates 
the ipv4 address and port into hexadecimal values for skbmark and skbmarkmask.
This script can also be used to view the sets in human readable form.
The script requires the ipset and awk utilites.

```
# load module
modprobe xt_NATMAP

# add set type hash:ip,port
# --skbinfo required!
# --counters for nformation or debug
ipset create nmap1 hash:ip,port --skbinfo --counters

iptables/ipnatset add nmap1 10.0.0.1,udp:1000 nat 10.0.0.3
iptables/ipnatset add nmap1 10.0.0.1,udp:2000 nat 10.0.0.2

iptables/ipnatset list

iptables -t nat -A PREROUTING  -j DNATMAP --nat-set nmap1 dst,dst
iptables -t nat -A POSTROUTING -j SNATMAP --nat-set nmap1 dst,dst

# testing
traceroute -4Un -N 1 -q 1 -p 1000 10.0.0.1
traceroute -4Un -N 1 -q 1 -p 2000 10.0.0.1
#
iptables/ipnatset list
```
