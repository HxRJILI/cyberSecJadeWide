#!/bin/bash

# Script to block an IP address using iptables
# Usage: ./block_ip.sh <IP_ADDRESS>

if [ $# -ne 1 ]; then
    echo "Usage: $0 <IP_ADDRESS>"
    exit 1
fi

IP_ADDRESS=$1

# Validate IP address format
if [[ ! $IP_ADDRESS =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    echo "Error: Invalid IP address format"
    exit 1
fi

# Log the blocking action
echo "$(date): Blocking IP address $IP_ADDRESS" >> /var/log/cybersec-blocks.log

# Block the IP using iptables
iptables -I INPUT -s $IP_ADDRESS -j DROP

# Verify the rule was added
if iptables -L INPUT | grep -q $IP_ADDRESS; then
    echo "Successfully blocked IP address: $IP_ADDRESS"
    exit 0
else
    echo "Failed to block IP address: $IP_ADDRESS"
    exit 1
fi