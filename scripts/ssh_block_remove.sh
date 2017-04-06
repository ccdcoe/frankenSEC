#!/bin/bash

ssh -p 22 root@firewall 'bash -s' -- <  /opt/SEC-IPS/scripts/iptables_remove.sh $1
