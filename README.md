# ipt_SNATMAP and ipt_DNATMAP

```
# load module
modprobe xt_NATMAP

# --skbinfo required!
# --counters for nformation or debug
ipset create nmap1 hash:ip,port --skbinfo --counters

iptables/ipnatset add nmap1 10.0.0.1,udp:1000 nat 10.0.0.3
iptables/ipnatset add nmap1 10.0.0.1,udp:2000 nat 10.0.0.2

iptables/ipnatset list

iptables -t nat -A PREROUTING  -j DNATMAP --nat-set nmap1 dst,dst
iptables -t nat -A POSTROUTING -j SNATMAP --nat-set nmap1 dst,dst

traceroute -4Un -N 1 -q 1 -p 1000 10.0.0.1
traceroute -4Un -N 1 -q 1 -p 2000 10.0.0.1
#
iptables/ipnatset list
```
