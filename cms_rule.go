package main

import (
	"crypto/sha512"
	"encoding/binary"
	"hash/fnv"
	"log"
	"sync"
	"time"

	"hash/adler32"
	"hash/crc32"

	"github.com/cespare/xxhash"
	"github.com/google/gopacket/layers"
)

var lastTimestamp time.Time

// CountMinSketch struct definition
type CountMinSketch struct {
	hashes           []func(string) uint32
	counts           [][]int
	numRows          int
	numCols          int
	mu               sync.Mutex
	threshold        int
	addressedDomains map[string]bool
}

// NewCountMinSketch creates a new CountMinSketch with specified dimensions
func NewCountMinSketch(numRows, numCols int, threshold int) *CountMinSketch {
	cms := &CountMinSketch{
		numRows:   numRows,
		numCols:   numCols,
		counts:    make([][]int, numRows),
		threshold: threshold,
	}
	for i := range cms.counts {
		cms.counts[i] = make([]int, numCols)
	}
	cms.addressedDomains = map[string]bool{}
	cms.hashes = []func(string) uint32{
		hashFunc1,
		hashFunc3,
		hashFunc4,
		hashFunc2,
		hashFunc5,
	}
	//get the amount of functions defined by our config
	cms.hashes = cms.hashes[:numRows]
	return cms
}

// hashFunc1 is a sample hash function
func hashFunc1(s string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(s))
	return h.Sum32()
}

// hashFunc2 is SHA-512
func hashFunc2(s string) uint32 {
	// Compute the SHA-512 hash
	hash := sha512.Sum512([]byte(s))
	return binary.BigEndian.Uint32(hash[:4])
}

// hashFunc3 is an alternative hash function using XXHash
func hashFunc3(s string) uint32 {
	return uint32(xxhash.Sum64([]byte(s)))
}

// hashFunc4 is another sample hash function using Adler32
func hashFunc4(s string) uint32 {
	return adler32.Checksum([]byte(s))
}

// hashFunc5 is another sample hash function using CRC32
func hashFunc5(s string) uint32 {
	return crc32.ChecksumIEEE([]byte(s))
}

// AddToCMS adds a value to the CountMinSketch
func AddToCMS(cms *CountMinSketch, value string, timestamp time.Time, index int) string {
	cms.mu.Lock()
	defer cms.mu.Unlock()
	for i, hashFunc := range cms.hashes {
		index := hashFunc(value) % uint32(cms.numCols)
		cms.counts[i][index]++
	}
	//check dominance
	dominant := GetDominantDomain(value)
	if dominant { //found an attack

		countAttacks += 1 //count the attacked packet

		if allreadyTCed(value) { // if the domain was allready addressed in this window
			log.Println("Too popular domain:", value, ";index: ", index, " - dropped!")
			return "D"
		}
		//if the domain is too popular, we mark it as TC
		log.Println("Too popular domain:", value, ";index: ", index)
		cms.addressedDomains[value] = true
		return "TC"

	}

	return "F"

}

// an estimate of the domains at hand
// EstimateFrequency estimates the count of a value in the CountMinSketch
func EstimateFrequency(cms *CountMinSketch, value string) int {

	// Initialize minCount to a large value
	minCount := cms.counts[0][cms.hashes[0](value)%uint32(cms.numCols)]

	for i, hashFunc := range cms.hashes {
		index := hashFunc(value) % uint32(cms.numCols)
		count := cms.counts[i][index]
		if count < minCount {
			minCount = count
		}
	}
	return minCount
}

// processPacket processes a network packet to extract DNS information
func cmsRule(dns *layers.DNS, timestamp time.Time, index int) string {
	//erase if the time is too long
	if lastTimestamp.IsZero() {

		lastTimestamp = timestamp
	} else {
		if timestamp.Sub(lastTimestamp) > W {

			cms = NewCountMinSketch(d, w, tau)
			//update last timestamp
			lastTimestamp = timestamp
		}
	}
	flag := "F"
	if len(dns.Answers) > 0 {
		ans := dns.Answers[0]
		if ans.Type == 5 { //skip CNAMEs, only count A/AAAA, etc.
			return "F"
		}
		domainName := string(ans.Name)

		mu.Lock()
		//domainCountMap[domainName]++
		flag = AddToCMS(cms, domainName, timestamp, index)
		mu.Unlock()
	}
	return flag

}

// GetDomainFrequency queries the CMS for the frequency of a given domain name
func GetDominantDomain(domain string) bool {
	return EstimateFrequency(cms, domain) > cms.threshold
}

// check if the domain in the TC packet was allready addresses in the current window
func allreadyTCed(domainName string) bool {
	_, exists := cms.addressedDomains[domainName]
	return exists
}
