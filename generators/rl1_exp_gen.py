from __future__ import division
import warnings
import time,os
import random,sys
from scapy.all import Ether, IP, UDP, DNS, DNSQR, DNSRR, wrpcap
import argparse
import numpy as np

#Get Tranco List's domains 
doms=[]
with open("domains.txt") as r:
    doms=[x.strip("\n") for x in r.readlines()]
r.close()


# Function to generate a random MAC address
def generate_random_mac():
    return ":".join([format(random.randint(0, 255), '02x') for _ in range(6)])

# Function to generate random DNS noise packets
def generate_noise_packets(count,src_ip,dst_ip):
    """Generates a specified number of random DNS noise packets."""
    noise_packets = []
    for _ in range(count):
        #Random source port for noise packets
        sport = random.randint(1024, 65535)
        dport = 53
        qname = doms[random.randint(1, len(doms))]
        
        
        # Create a noise DNS response
        transaction_id = random.randint(0, 65535)
        src_mac = generate_random_mac()
        dst_mac = generate_random_mac()
        noise_packet = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / \
                        UDP(sport=dport, dport=sport) / DNS(id=transaction_id, qr=1, aa=1, qd=DNSQR(qname=qname), \
                        rcode=0, an=DNSRR(rrname=qname, rdata=f"198.51.100.{random.randint(1, 254)}", ttl=300))
    
        noise_packets.append(noise_packet)
    return noise_packets

# Identify spoofed and noise packets
def is_spoofed(pkt):
    # Check for your fake_ip in the answer section
    return pkt.haslayer(DNSRR) and getattr(pkt[DNSRR], "rdata", None) == fake_ip

def is_noise(pkt):
    # Check for your noise IP range
    return pkt.haslayer(DNSRR) and str(pkt[DNSRR].rdata).startswith("198.51.100.")


# Argument parsing
parser = argparse.ArgumentParser(description="Generate DNS attack PCAP with interleaved noise.")
parser.add_argument("--resolver-ip", default="192.168.1.1", help="IP address of the DNS resolver")
parser.add_argument("--resolver-mac", default=None, help="MAC address of the DNS resolver (random if not set)")
parser.add_argument("--authoritative-ip", default="192.168.1.3", help="IP address of the authoritative DNS server")
parser.add_argument("--authoritative-mac", default=None, help="MAC address of the authoritative DNS server (random if not set)")
parser.add_argument("--client-ip", default="192.168.1.2", help="IP address of the client")
parser.add_argument("--client-mac", default=None, help="MAC address of the client (random if not set)")
parser.add_argument("--target-domain", default="example.com", help="Target domain for the attack")
parser.add_argument("--fake-ip", default="6.6.6.6", help="Fake IP address to use in spoofed responses")
parser.add_argument("--num-queries", type=int, default=1, help="Number of DNS queries to send")
parser.add_argument("--s-per-query", type=int, default=65535, help="Number of spoofed responses per query")
parser.add_argument("--noise", type=int, default=1000, help="Number of noise packets to add per query")
parser.add_argument("--out", default="../attack_pcaps", help="Output directory for the pcap file")

args = parser.parse_args()

# Assign arguments or generate random MACs if not provided
resolver_ip = args.resolver_ip
resolver_mac = args.resolver_mac or generate_random_mac()
authoritative_ip = args.authoritative_ip
authoritative_mac = args.authoritative_mac or generate_random_mac()
client_ip = args.client_ip
client_mac = args.client_mac or generate_random_mac()
target_domain = args.target_domain
fake_ip = args.fake_ip
num_queries = args.num_queries
num_spoofed_responses_per_query = args.s_per_query
noise_packet_count_per_query = args.noise

# Function to create DNS query packets for random subdomains
def create_dns_queries(client_ip, client_mac, resolver_ip, resolver_mac, domain, num_queries):
    packets = []
    for _ in range(num_queries):
        subdomain = f"{random.randint(1, 10000)}.{domain}"
        query_cl = Ether(src=client_mac, dst=resolver_mac) / IP(src=client_ip, dst=resolver_ip) / UDP(sport=random.randint(1024, 65535), dport=53) / DNS(rd=1, qd=DNSQR(qname=subdomain))
        query_res = Ether(src=resolver_mac, dst=authoritative_mac) / IP(src=resolver_ip, dst=authoritative_ip) / UDP(sport=random.randint(1024, 65535), dport=53) / DNS(rd=1, qd=DNSQR(qname=subdomain))

        packets.append(query_cl)
        packets.append(query_res)
    return packets

# Function to create spoofed DNS response packets with NS record
def create_spoofed_responses(resolver_ip, resolver_mac, authoritative_ip, authoritative_mac, query, num_responses):
    responses = []
    for i in range(num_responses):
        transaction_id = i
        spoofed_response = Ether(src=authoritative_mac, dst=resolver_mac) / \
                           IP(src=authoritative_ip, dst=resolver_ip) / \
                           UDP(sport=53, dport=query[UDP].sport) / \
                           DNS(id=transaction_id, qr=1, aa=1, qd=DNSQR(qname=query[DNSQR].qname), \
                           rcode=0,  # No error
                           an=DNSRR(rrname=query[DNSQR].qname, rdata=fake_ip, ttl=300), \
                           ns=DNSRR(rrname=query[DNSQR].qname, type="NS", rdata="ns.example.com", ttl=300), \
                           ar=DNSRR(rrname="ns.example.com", rdata=fake_ip, ttl=300))
        responses.append(spoofed_response)
    return responses

# Function to create a legitimate DNS response indicating non-existent domain
def create_legitimate_response(resolver_ip, resolver_mac, authoritative_ip, authoritative_mac, query):
    legitimate_response = Ether(src=authoritative_mac, dst=resolver_mac) / \
                          IP(src=authoritative_ip, dst=resolver_ip) / \
                          UDP(sport=53, dport=query[UDP].sport) / \
                          DNS(id=query[DNS].id, qr=1, aa=1, qd=DNSQR(qname=query[DNSQR].qname), \
                          rcode=3)  # rcode=3 means non-existent domain
    return legitimate_response


# Generate DNS queries
dns_queries = create_dns_queries(client_ip, client_mac, resolver_ip, resolver_mac, target_domain, num_queries)
all_pacs=[]
# Combine the DNS queries, spoofed responses, and noise packets
i=0
while i <(len(dns_queries)):
    
    query=dns_queries[i]
    packets = []

    # Add the query packet
    packets.append(dns_queries[i])
    packets.append(dns_queries[i+1])
    #Increment i to skip the resolver's query to the authoritative server
    i+=2
    # Create spoofed responses
    spoofed_responses = create_spoofed_responses(resolver_ip, resolver_mac, authoritative_ip, authoritative_mac, query, num_spoofed_responses_per_query)

    # Generate noise packets
    noise_packets = generate_noise_packets(noise_packet_count_per_query,args.authoritative_ip,args.resolver_ip)

    # Combine spoofed responses and noise packets
    combined_responses_and_noise = spoofed_responses + noise_packets

    # Shuffle the combined list to randomize order
    random.shuffle(combined_responses_and_noise)

    # Add the combined spoofed responses and noise to the packet list
    packets.extend(combined_responses_and_noise)

    # Add the legitimate response packet
    legitimate_response = create_legitimate_response(resolver_ip, resolver_mac, authoritative_ip, authoritative_mac, query)
    packets.append(legitimate_response)


        
    # Assign times
    spoofed_indices = [i for i, p in enumerate(packets) if is_spoofed(p)]
    noise_indices = [i for i, p in enumerate(packets) if is_noise(p)]

    start_time = time.time()

    # Spoofed: evenly spaced between start_time and start_time+0.4s
    if spoofed_indices:
        spoofed_times = np.linspace(start_time, start_time + 0.4, num=len(spoofed_indices))
        for idx, t in zip(spoofed_indices, spoofed_times):
            packets[idx].time = t

    # Noise: randomly distributed in [start_time, start_time+1.0]
    if noise_indices:
        noise_times = np.sort(np.random.uniform(start_time, start_time + 1.0, size=len(noise_indices)))
        for idx, t in zip(noise_indices, noise_times):
            packets[idx].time = t

    # For all other packets (queries, legit responses), assign at the very start (or as you wish)
    for j, p in enumerate(packets):
        if not hasattr(p, "time"):
            p.time = start_time + 0.001 * j  # Spread a bit at the start

    # Sort packets by time before writing
    packets.sort(key=lambda p: p.time)
    # Add the packets to the all_pacs list
    all_pacs.extend(packets)


os.makedirs(args.out,exist_ok=True)
# Write packets to a pcap file
pcap_filename = f"{args.out}/guessing_attack_with_interleaved_noise_{noise_packet_count_per_query}_packets_rand_{random.randint(1, 10000)}.pcap"
wrpcap(pcap_filename,all_pacs)
print(f"DNS attack interleaved with {noise_packet_count_per_query} noisy packets have been written to {pcap_filename}")
