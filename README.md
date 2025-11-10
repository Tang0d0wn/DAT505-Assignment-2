# ARP Spoofing & DNS MITM with Scapy

This repo contains the scripts using the Scapy library, the following Task done in Assignment 2 is:
1. ARP Spoofing
2. Traffic Capture & Analysis
3. DNS Spoofing

Additionally, scripts, capture files (pcap), images, and CSV logs produced during the tasks.
   

## Folder Structure
```
evidence/
├── Arp_spoof_evidence/
│ ├── after_arp_spoofing_server.png
│ ├── after_arp_spoofing_victim.png
│ ├── before_server.png
│ ├── before_victim.png
│ ├── WireSharkCAp.png
│ └── WireSharkCAptureARPSpoofing.png
│
├── DNS_Spoof_evidence/
│ ├── afterDNSSpoof.png
│ ├── beforeDNSSpoof.png
│ └── WiresharpcaptureDNSfilter.png
│
└── Traffic_intercept_evidence/
└── traffic.csv

pcapfiles/
├── arp_spoof2.pcap
└── traffic.pcap

scripts/
├── arp_spoof.py
├── dns_spoof.py
├── index.html
├── spoof_target.conf
└── traffic_interceptor.py

requirement.txt
```
## Network Setup
The network contains three virtual machines on an isolated network:

- **Apache-Server:** 10.0.2.15  
- **Attacker-Machine:** 10.0.2.16  
- **Victim-Machine:** 10.0.2.17  
- **Interface:** `eth0` (used by all VMs)

## Requirement and Installation


To run the scripts you need:

1. **Python 3**
2. **Scapy**

Kali Linux includes Python by default, but you may need to install Scapy.

### Installing Scapy (Debian / Kali)

```bash
# update package lists
sudo apt update

# install the system package for Scapy
sudo apt install -y python3-scapy
```


## Task 1 - ARP Spoof Instructions
Run these commands from the **Attacker** and **Victim** machines in separate terminals.

### 1. On the Attacker — terminal 1: capture traffic with `tcpdump`
Start the packet capture before launching the exploit so you record all traffic:

```bash
sudo tcpdump -i eth0 -w arp_spoof.pcap -s 0
```
In a second terminal run the spoofing script :
```bash
# Starts the script on the second terminal
sudo python3 arp_spoof.py
```
Then on the victim, generate traffic to the server:
```bash
#Pinging the Apache Server
ping 10.0.2.15 
```
To stop the process simply do `Ctrl+C`

## Task 2 - Traffic Intercept Instructions

### 1. On the Attacker VM — run the interceptor
Start the traffic interception script:
```bash
sudo python3 traffic_intercept.py
```
The victim VM's need to generate HTTP and DNS traffic:
```bash
# Generate DNS and HTTP traffic
#10 DNS lookups
for i in {1..10}; do nslookup kali.local;done
#10 HTTP Requests
for i in {1..10}; do curl http://10.0.2.15:80;done
```
Each of these sends 10 requests. 
To stop the process simply do `Ctrl+C`

## Task 3 - DNS Spoof Instructions
The attacker needs two terminals open:

- **Terminal 1:** run ARP spoofing (`arp_spoof.py`) to place the attacker between victim and server.  
- **Terminal 2:** run DNS spoofing (`dns_spoof.py`) to answer DNS queries for targeted names.

NB!(Make sure `dns_spoof.py` and `spoof_targets.conf` are in the **same directory** when you run the DNS spoofing script)

### 1. Start ARP spoofing (Attacker — Terminal 1)
```bash
# start the ARP spoofing 
sudo python3 arp_spoof.py
```
### 2. Start DNS spoofing (Attacker — Terminal 2)
```bash
# start the DNS spoofing 
sudo python3 arp_spoof.py
```
### 3. Go to the URL or curl it
From the Victim you can simply open a web browser(e.g FireFox) and enter the domain name "kali.local" or you can do it in the terminal:
```bash
firefox kali.local
or
curl -I http://kali.local
```
To verify it works: 

```bash
#query DNS
dig kali.local +short

#Excpected Output:
10.0.16
```
To stop the process simply do `Ctrl+C`
