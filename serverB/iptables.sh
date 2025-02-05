#!/bin/sh

IPT=/sbin/iptables
# NAT interface
NIF=enp0s5
# NAT IP address
NIP=`ip addr show enp0s5 | grep -Po 'inet \K[\d.]+'`

# Local subnet (host-only)
LIF=enp0s6
# Host-only IP addres
LIP='192.168.80.100'

# VPN interface (host-only)
VIF=enp0s7
# Host-only IP addres
VIP='192.168.70.6'

# DNS nameserver 
NS='127.0.0.53'

## Reset the firewall to an empty, but friendly state

# Flush all chains in FILTER table
$IPT -t filter -F
# Delete any user-defined chains in FILTER table
$IPT -t filter -X
# Flush all chains in NAT table
$IPT -t nat -F
# Delete any user-defined chains in NAT table
$IPT -t nat -X
# Flush all chains in MANGLE table
$IPT -t mangle -F
# Delete any user-defined chains in MANGLE table
$IPT -t mangle -X
# Flush all chains in RAW table
$IPT -t raw -F
# Delete any user-defined chains in RAW table
$IPT -t mangle -X

# Default policy is to send to a dropping chain
#$IPT -t filter -P INPUT ACCEPT
#$IPT -t filter -P OUTPUT ACCEPT
#$IPT -t filter -P FORWARD ACCEPT

# Task 15
# Default policy is to DROP traffic
$IPT -t filter -P INPUT DROP
$IPT -t filter -P OUTPUT DROP
$IPT -t filter -P FORWARD DROP

# Task 14
# Block HTTP traffic (port 80)
#$IPT -A INPUT -p tcp --dport 80 -j DROP

# Task 16
# Create logging chains
$IPT -t filter -N input_log
$IPT -t filter -N output_log
$IPT -t filter -N forward_log
# Set some logging targets for DROPPED packets
$IPT -t filter -A input_log -j LOG --log-level notice --log-prefix "input drop: " 
$IPT -t filter -A output_log -j LOG --log-level notice --log-prefix "output drop: " 
$IPT -t filter -A forward_log -j LOG --log-level notice --log-prefix "forward drop: " 
echo "Added logging"
# Return from the logging chain to the built-in chain
$IPT -t filter -A input_log -j RETURN
$IPT -t filter -A output_log -j RETURN
$IPT -t filter -A forward_log -j RETURN

# Task 17
# Allow all traffic to/from loopback interface (lo)
$IPT -A INPUT -i lo -j ACCEPT
$IPT -A OUTPUT -o lo -j ACCEPT
# Allow ICMP (ping) to/from loopback interface
$IPT -A INPUT -p icmp --icmp-type echo-request -i lo -j ACCEPT
$IPT -A OUTPUT -p icmp --icmp-type echo-reply -o lo -j ACCEPT
# Allow SSH traffic (port 22) to/from loopback interface
$IPT -A INPUT -p tcp --dport 22 -i lo -j ACCEPT
$IPT -A OUTPUT -p tcp --sport 22 -o lo -j ACCEPT

# Task 18
# Allow outgoing ICMP Echo Request from Server A 
#$IPT -A OUTPUT -p icmp --icmp-type echo-request -s 192.168.60.100 -j ACCEPT
# Allow incoming ICMP Echo Reply to Server A 
#$IPT -A INPUT -p icmp --icmp-type echo-reply -d 192.168.60.100 -j ACCEPT

# Task 19
# Allow DNS queries (UDP and TCP) to the DNS server
$IPT -A OUTPUT -p udp --dport 53 -j ACCEPT
$IPT -A OUTPUT -p tcp --dport 53 -j ACCEPT
# Allow DNS responses (UDP and TCP) from the DNS server
$IPT -A INPUT -p udp --sport 53 -j ACCEPT
$IPT -A INPUT -p tcp --sport 53 -j ACCEPT
# Allow outgoing ICMP Echo Requests (ping)
$IPT -A OUTPUT -p icmp --icmp-type echo-request -j ACCEPT
# Allow incoming ICMP Echo Replies
$IPT -A INPUT -p icmp --icmp-type echo-reply -j ACCEPT
# Block all other types of ICMP traffic to/from external networks
$IPT -A INPUT -p icmp -j DROP
$IPT -A OUTPUT -p icmp -j DROP

# Task 22
# Allow incoming ICMP Echo Requests (ping)
$IPT -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
# Allow outgoing ICMP Echo Replies
$IPT -A OUTPUT -p icmp --icmp-type echo-reply -j ACCEPT


# Task 20
# Allow established and related connections for incoming traffic
$IPT -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
# Allow established and related connections for outgoing traffic
$IPT -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
# Allow new outgoing TCP connections (e.g., for HTTP/HTTPS browsing)
$IPT -A OUTPUT -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT
$IPT -A OUTPUT -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT

# Task 21
# Enable SSH traffic on port 10022
# Allow SSH from host OS
$IPT -A INPUT -p tcp -s 192.168.60.2 --dport 22 -j ACCEPT
# Allow outgoing SSH (for Server A to SSH out)
$IPT -A OUTPUT -p tcp --dport 22 -j ACCEPT
# Enable HTTPS traffic for Apache2 server on port 10443
$IPT -A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -p tcp --sport 443 -m conntrack --ctstate ESTABLISHED -j ACCEPT

# Task 23
# Allow SSH from clientA (replace 192.168.60.111 with actual IP of clientA)
iptables -A INPUT -p tcp -s 192.168.60.111 --dport 22 -j ACCEPT

# Task 26
$IPT -t filter -A FORWARD -i $LIF -j ACCEPT
$IPT -t filter -A FORWARD -i $NIF -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Task 27
$IPT -t nat -A POSTROUTING -j SNAT -o $NIF --to $NIP



# Lab 2

# Set up iptables rules for secure communication and routing between subnets.



# Allow established and related connections for incoming and outgoing traffic.

$IPT -t filter -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

$IPT -t filter -A OUTPUT -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT



# Allow SSH traffic (port 22) for secure remote access.

$IPT -A INPUT -p tcp --dport 22 -j ACCEPT

$IPT -A OUTPUT -p tcp --sport 22 -j ACCEPT



# Allow all traffic on the VPN interface.

$IPT -A INPUT -i $VIF -j ACCEPT

$IPT -A OUTPUT -o $VIF -j ACCEPT

$IPT -A FORWARD -i $VIF -j ACCEPT

$IPT -A FORWARD -o $VIF -j ACCEPT



# Allow forwarding between the private subnets 192.168.70.0/24 and 192.168.80.0/24.

$IPT -A FORWARD -s 192.168.70.0/24 -d 192.168.80.0/24 -j ACCEPT

$IPT -A FORWARD -s 192.168.80.0/24 -d 192.168.70.0/24 -j ACCEPT



# Set up NAT for outbound traffic from the local network to the public network.

$IPT -t nat -A POSTROUTING -o $NIF -j MASQUERADE



# Allow forwarding between the Local subnet and the NAT interface.

$IPT -t filter -A FORWARD -i $LIF -o $NIF -j ACCEPT

$IPT -t filter -A FORWARD -i $NIF -o $LIF -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT



# Task 16
# These rules must be inserted at the end of the built-in
# chain to log packets that will be dropped by the default
# DROP policy
$IPT -t filter -A INPUT -j input_log
$IPT -t filter -A OUTPUT -j output_log
$IPT -t filter -A FORWARD -j forward_log

