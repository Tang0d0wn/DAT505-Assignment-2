from scapy.all import *
from collections import Counter
import csv
import time

c = Counter()
ips = Counter()
packets = []
csv_file = open('traffic.csv', 'w', newline='')
csv_writer = csv.writer(csv_file)
csv_writer.writerow(['Time', 'Type', 'Details'])

def traffic_intercept(pkt):
    global c, ips, packets, csv_file, csv_writer
    
    print(f"Packet received: {pkt.summary()}")
    packets.append(pkt)
    
    if IP in pkt:
        ips[pkt[IP].src] += 1
        ips[pkt[IP].dst] += 1
    
    if TCP in pkt:
        c['TCP'] += 1
        if pkt[TCP].dport in (80, 8080) or pkt[TCP].sport in (80, 8080):
            c['HTTP'] += 1
            if Raw in pkt and b"GET" in pkt[Raw].load:
                url = f"http://{pkt[IP].dst}{pkt[Raw].load.split()[1].decode()}"
                print(f"URL → {url}")
                csv_writer.writerow([time.strftime('%Y-%m-%d %H:%M:%S'), 'URL', url])
        elif pkt[TCP].dport == 22 or pkt[TCP].sport == 22:
            c['SSH'] += 1
        elif pkt[TCP].dport in (20, 21) or pkt[TCP].sport in (20, 21):
            c['FTP'] += 1
        if pkt[TCP].dport == 80 or pkt[TCP].sport == 80:
            print(f"TCP 80 → {pkt[IP].src}:{pkt[TCP].sport} to {pkt[IP].dst}:{pkt[TCP].dport}")
            csv_writer.writerow([time.strftime('%Y-%m-%d %H:%M:%S'), 'HTTP_80',
                               f"{pkt[IP].src}:{pkt[TCP].sport} to {pkt[IP].dst}:{pkt[TCP].dport}"])
    
    if UDP in pkt:
        c['UDP'] += 1
        if pkt[UDP].dport == 53 or pkt[UDP].sport == 53:
            c['DNS'] += 1
            if DNSQR in pkt:
                qname = pkt[DNSQR].qname.decode().strip('.')
                print(f"DNS → {qname}")
                csv_writer.writerow([time.strftime('%Y-%m-%d %H:%M:%S'), 'DNS', qname])
    
    if ICMP in pkt:
        c['ICMP'] += 1
    
    if sum(ips.values()) % 50 == 0:
        print("\nTop Talkers:", ips.most_common(5), "\nProtocols:", dict(c))

print("Starting the traffic sniff sniff...")
sniff(iface="eth0", prn=traffic_intercept, store=0, timeout=60)
print(f"Stopping... Packets captured: {len(packets)}")
print(f"First packet: {packets[0].summary() if packets else 'None'}")
csv_file.close()
if packets:
    try:
        wrpcap('traffic.pcap', packets)
        print("PCAP saved.")
    except Exception as e:
        print(f"Failed: {e}")
else:
    print("No packets to save.")

