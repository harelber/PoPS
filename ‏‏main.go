package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const batchSize = 1000 // Define the batch size for practicall processing
var d = 5              // the d in CMS, number of hash functions
var w = 5              // the w in cms, number of columns

const tau = 5             //threshold for popular domain
const W = 1 * time.Second // value of window

var countAttacks = 0 //count the number of attack packets - for documentation
var totalPackets = 0 //count the number of total packets - for documention

func flipTCFlag(rawPacketBytes []byte, dnsStartIndex int) {
	// The TC flag is the 6th bit in the 3rd byte of the DNS header
	rawPacketBytes[dnsStartIndex+2] |= 1 << 1
}

// /packet number and index
type PacNumber struct {
	Pac gopacket.Packet
	Ind int
}

// Global variables
var (
	cms = NewCountMinSketch(d, w, tau)
	mu  sync.Mutex
)

func main() {
	//variables for getting the args from the user
	var (
		iface      string
		pcapFile   string
		filterIP   string
		hashesNum  int
		counterNum int
	)

	// Command-line flags
	flag.StringVar(&iface, "i", "", "Network interface to capture packets from")
	flag.StringVar(&pcapFile, "r", "", "PCAP file to read packets from")
	flag.StringVar(&filterIP, "d", "", "Destination IP to filter DNS responses")
	flag.IntVar(&hashesNum, "h", 3, "amount of hash functions")
	flag.IntVar(&counterNum, "c", 5, "amount of hash functions")
	flag.Parse()
	//update the rows/cols
	d = hashesNum
	w = counterNum
	if iface == "" && pcapFile == "" {
		log.Fatal("You must specify either a network interface (-i) or a pcap file (-r)")
	}

	if filterIP == "" {
		log.Fatal("You must specify a resolver IP to filter DNS responses (-d)")
	}

	var handle *pcap.Handle
	var err error

	if pcapFile != "" {
		// Read from pcap file
		handle, err = pcap.OpenOffline(pcapFile)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		// Capture live packets
		handle, err = pcap.OpenLive(iface, 65536, true, pcap.BlockForever)
		if err != nil {
			log.Fatal(err)
		}
	}
	defer handle.Close()
	log.Println("Starting...")
	// Set BPF filter to capture only DNS responses to the specified IP
	bpfFilter := fmt.Sprintf("dst host %s", filterIP)
	if err := handle.SetBPFFilter(bpfFilter); err != nil {
		log.Fatal(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	batch := make([]PacNumber, 0, batchSize)
	log.Println("Batching & Processing...")
	cms = NewCountMinSketch(d, w, tau)
	//iteration of packets based on batches
	for packet := range packetSource.Packets() {
		p := PacNumber{Pac: packet, Ind: totalPackets}
		batch = append(batch, p)
		totalPackets++ //count the packets
		if len(batch) >= batchSize {
			processBatch(batch)
			batch = batch[:0] // Reset the batch
		}
	}

	// Process any remaining packets in the batch
	if len(batch) > 0 {
		processBatch(batch)
	}
	log.Println("Finished processing!! Here are the statistics...")
	//lof the amount of identified packets
	log.Println("File:", pcapFile, ";Suspicious:", countAttacks, ";Total:", totalPackets)
}

// processing the batch if packets
func processBatch(batch []PacNumber) {

	for _, packet := range batch {
		processPacket(packet)
	}
}

// process each packet
func processPacket(pac PacNumber) {

	packet := pac.Pac //the packet
	ind := pac.Ind    //the packet index
	ipLayer := packet.Layer(layers.LayerTypeIPv4)

	if ipLayer == nil {
		return
	}

	ip, _ := ipLayer.(*layers.IPv4)
	//calculate the rawbyes sum
	rawPacketBytes := packet.Data()
	// Calculate the starting index of the DNS header
	ipHeaderLen := int(ip.IHL) * 4

	//get the timestamp
	timestamp := packet.Metadata().Timestamp

	//second fragment - ignore
	if ip.FragOffset != 0 {
		//please fix here to send
		log.Println("ignoring second fragment")
		return
	}

	// first fragment - send TC
	if ip.Flags&layers.IPv4MoreFragments != 0 {

		log.Println("checking first fragment", ind)

		// Manually extract the UDP header from the IP payload
		payload := ip.Payload
		if len(payload) < 8 {
			log.Println("Payload too short for UDP header")
			os.Exit(0)
		}
		log.Println("first fragment - another optional attack vector, timestamp ", timestamp)
		log.Println("but use the mitigation")
		rawB, err := createDNSResponseFrag(ip, payload)
		if err != nil {
			log.Printf("error in creating new DNS response for fragment %v", err)
		}
		countAttacks += 1

		// Manually extract destination port for sending
		dstPort := binary.BigEndian.Uint16(payload[2:4])

		// Send the raw packet
		sendRawPacketfrag(ip, rawB, dstPort)
		return
	} else { //move to check bailiwick and CMS table for guessing
		udpHeaderLen := 8 // UDP header length is always 8 bytes
		dnsStartIndex := ipHeaderLen + udpHeaderLen
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer == nil { //eliminate count of non-dns packets in this stage
			totalPackets -= 1
			return
		}
		udp, _ := udpLayer.(*layers.UDP)

		dnsLayer := packet.Layer(layers.LayerTypeDNS)
		if dnsLayer == nil {
			// Send the raw packet bytes
			sendPacket(ip, udp, rawPacketBytes)
			totalPackets -= 1 //eliminate count of non-dns packets in this stage
			return
		}
		dns, _ := dnsLayer.(*layers.DNS)
		if !dns.QR { //check only dns responses
			// Send the raw packet bytes
			sendPacket(ip, udp, rawPacketBytes)
			totalPackets -= 1 //eliminate count of non-dns packets in this stage
			return
		}
		//check for bailiwick rule violation
		if enforceBailiwick(dns, timestamp) {
			//will drop the packet and not move forward
			flipTCFlag(rawPacketBytes, dnsStartIndex)

		} else {

			//check for multiple packets
			//with the same id/ports
			result := cmsRule(dns, timestamp, ind)
			switch result {
			case "TC": //truncate the message and forward it
				flipTCFlag(rawPacketBytes, dnsStartIndex)
			case "D": //will drop the packet and not move forward, as it was allready addressed
				return
			default:
			}

		}
		// Send the raw packet bytes
		sendPacket(ip, udp, rawPacketBytes)
	}

}

// send final packet to the resolver
func sendPacket(ip *layers.IPv4, udp *layers.UDP, rawPacketBytes []byte) {
	addr := net.UDPAddr{
		IP:   ip.DstIP,
		Port: int(udp.DstPort),
	}

	conn, err := net.DialUDP("udp", nil, &addr)
	if err != nil {
		log.Println("Failed to dial:", err)
		return
	}
	defer conn.Close()

	_, err = conn.Write(rawPacketBytes)
	if err != nil {
		log.Println("Failed to send packet:", err)
	}
}

func createDNSResponseFrag(ip *layers.IPv4, payload []byte) ([]byte, error) {
	if len(payload) < 8 {
		return nil, fmt.Errorf("payload too short for UDP header")
	}

	// Manually parse UDP header
	srcPort := binary.BigEndian.Uint16(payload[0:2])
	dstPort := binary.BigEndian.Uint16(payload[2:4])
	udpLength := binary.BigEndian.Uint16(payload[4:6])

	// Check if the payload has enough data for UDP and DNS
	udpPayload := payload[8:]
	if len(udpPayload) < int(udpLength-8) {
		return nil, fmt.Errorf("udp payload too short for dns")
	}

	// Manually parse DNS header
	dnsID := binary.BigEndian.Uint16(udpPayload[0:2])
	flags := binary.BigEndian.Uint16(udpPayload[2:4])

	// Construct DNS response with same ID and question as the query
	responseDNS := &layers.DNS{
		ID:           dnsID,
		QR:           true, // Response
		OpCode:       layers.DNSOpCode(flags >> 11),
		AA:           true, // Authoritative answer
		RA:           true, // Recursion Available
		ResponseCode: layers.DNSResponseCodeNoErr,
		TC:           true, //set TC
	}

	// Manually add questions and answers for the response
	// Here we add one A record as a response (e.g., 192.168.1.1)
	responseDNS.Questions = []layers.DNSQuestion{
		{
			Name:  udpPayload[12:], // This is an example; adjust for actual name parsing
			Type:  layers.DNSTypeA,
			Class: layers.DNSClassIN,
		},
	}
	responseDNS.Answers = []layers.DNSResourceRecord{}

	// Prepare the UDP layer for the response
	responseUDP := layers.UDP{
		SrcPort: layers.UDPPort(dstPort),
		DstPort: layers.UDPPort(srcPort),
	}
	responseUDP.SetNetworkLayerForChecksum(ip)

	// Prepare the IP layer for the response
	responseIP := layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    ip.DstIP,
		DstIP:    ip.SrcIP,
	}

	// Serialize the response packet
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if err := gopacket.SerializeLayers(buffer, opts, &responseIP, &responseUDP, responseDNS); err != nil {
		return nil, fmt.Errorf("could not serialize layers: %v", err)
	}

	return buffer.Bytes(), nil
}

// Function to send the raw packet over a UDP connection
func sendRawPacketfrag(ip *layers.IPv4, rawPacketBytes []byte, dstPort uint16) {
	srcPort := 53 // Typical DNS source port
	srcAddr := net.UDPAddr{
		IP:   ip.DstIP, // The source address should be the packet's destination IP in the response
		Port: int(srcPort),
	}

	dstAddr := net.UDPAddr{
		IP:   ip.SrcIP, // Destination address for the response
		Port: int(dstPort),
	}

	conn, err := net.DialUDP("udp", &srcAddr, &dstAddr)
	if err != nil {
		log.Println("Failed to dial:", err)
		return
	}
	defer conn.Close()

	_, err = conn.Write(rawPacketBytes)
	if err != nil {
		log.Println("Failed to send raw packet:", err)
	}
}
