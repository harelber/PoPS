import argparse
import random
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether

def random_mac():
    return "02:%02x:%02x:%02x:%02x:%02x" % tuple(random.randint(0, 255) for _ in range(5))

parser = argparse.ArgumentParser(description="Generate out-of-bailiwick DNS query/response PCAP")
parser.add_argument("--resolver-ip", default="192.168.1.1", help="IP address of the DNS resolver (query sender)")
parser.add_argument("--resolver-mac", default=None, help="MAC address of the DNS resolver (random if not set)")
parser.add_argument("--authoritative-ip", default="192.168.1.2", help="IP address of the authoritative DNS server (response sender)")
parser.add_argument("--authoritative-mac", default=None, help="MAC address of the authoritative server (random if not set)")
parser.add_argument("--domain", default="example.com", help="Domain name to query (default: example.com)")
parser.add_argument("--output", default="../attack_pcaps/out_of_bailiwick.pcap", help="Output PCAP file name")
parser.add_argument("--oob", default="ns.abc.com", help="Out of bailiwick domain")

args = parser.parse_args()

resolver_mac = args.resolver_mac or random_mac()
authoritative_mac = args.authoritative_mac or random_mac()
domain = args.domain

# Ethernet layers
eth_query = Ether(src=resolver_mac, dst=authoritative_mac)
eth_response = Ether(src=authoritative_mac, dst=resolver_mac)

# IP/UDP layers for query (resolver -> authoritative)
ip_query = IP(src=args.resolver_ip, dst=args.authoritative_ip)
udp_query = UDP(sport=33333, dport=53)

# DNS query
dns_query = DNS(
    id=0xAAAA,
    qr=0,
    opcode=0,
    rd=1,
    qdcount=1,
    qd=DNSQR(qname=domain, qtype="A")
)
query_packet = eth_query / ip_query / udp_query / dns_query

# IP/UDP layers for response (authoritative -> resolver)
ip_response = IP(src=args.authoritative_ip, dst=args.resolver_ip)
udp_response = UDP(sport=53, dport=33333)

# DNS response (out-of-bailiwick)
dns_response = DNS(
    id=dns_query.id,
    qr=1,
    aa=0,
    rd=1,
    ra=1,
    qd=dns_query.qd,
    ancount=1,
    nscount=1,
    arcount=1,
    an=DNSRR(rrname=domain, rdata="198.51.100.1", ttl=300),
    ns=DNSRR(rrname=domain, type="NS", rdata=args.oob, ttl=300),
    ar=DNSRR(rrname=args.oob, type="A", rdata="6.6.6.6", ttl=300)
)
response_packet = eth_response / ip_response / udp_response / dns_response

# Write to PCAP
wrpcap(args.output, [query_packet, response_packet])
print(f"Out of bailiwick DNS packets have been written to {args.output}")