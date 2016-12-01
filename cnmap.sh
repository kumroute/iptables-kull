#!/usr/bin/env bash
sudo /home/kumroute/Documentos/Firewall/iptables.sh stop_quiet
sudo nmap $* ; echo
sudo /home/kumroute/Documentos/Firewall/iptables.sh start_quiet
