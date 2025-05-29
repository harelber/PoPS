package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/gopacket/layers"
)

var analyzedTypes = []int{1, 2, 5, 15, 16, 28} //known DNS query types relevant to study

// Simulated constant map created from the types
var lookupMap = func() map[int]struct{} {
	m := make(map[int]struct{}, len(analyzedTypes))
	for _, v := range analyzedTypes {
		m[v] = struct{}{}
	}
	return m
}()

// Function to check if a target is in the simulated constant map
func contains(target int) bool {
	_, found := lookupMap[target]
	return found
}

// EnforceBailiwick checks if the DNS response meets the bailiwick rule
func enforceBailiwick(dns *layers.DNS, timestamp time.Time) bool {

	// Determine bailiwick from the DNS question section
	for _, question := range dns.Questions {
		if !contains(int(question.Type)) { //check if the response is in the analyzed type
			return false
		}
		bailiwick := []string{extractDomain(string(question.Name))}

		// Check answers
		for _, answer := range dns.Answers {

			//add cnames to the bailiwicks
			if answer.Type == 5 { //a cname
				bailiwick = append(bailiwick, strings.ToLower(string(answer.CNAME)))
				continue
			}

			if !isWithinBailiwick(strings.ToLower(string(answer.Name)), bailiwick) {
				fmt.Println("Out of bailiwich packet in timestamp ", timestamp, "- answer", strings.ToLower(string(answer.Name)))
				countAttacks += 1 //bailiwick suspicous
				return true
			}
		}
		// Check authuritatives
		for _, answer := range dns.Authorities {

			if !isWithinBailiwickAuth(strings.ToLower(string(answer.Name)), bailiwick, string(question.Name)) {

				fmt.Println("Out of bailiwich packet in timestamp ", timestamp, "- auth", strings.ToLower(string(answer.Name)))
				countAttacks += 1 //bailiwick suspicous
				return true
			}

		}
		// Check additionals
		for _, answer := range dns.Additionals {

			if !isWithinBailiwick(strings.ToLower(string(answer.Name)), bailiwick) {
				if strings.Contains(strings.ToLower(string(answer.Name)), "root-servers") {
					continue
				}
				if strings.Contains(strings.ToLower(string(answer.Name)), "tld") {
					continue
				}
				fmt.Println("Out of bailiwich packet in timestamp ", timestamp, "- add", strings.ToLower(string(answer.Name)))
				countAttacks += 1 //bailiwick suspicous
				return true
			}
		}
	}
	return false
}

// ExtractDomain extracts the main domain from a DNS name
func extractDomain(name string) string {
	parts := strings.Split(name, ".")
	if len(parts) < 2 {
		return name
	}

	return strings.ToLower(strings.Join(parts[len(parts)-2:], "."))
}

// IsWithinBailiwick checks if a domain is within the bailiwick of a specified domain
func isWithinBailiwick(domain string, bailiwick []string) bool {
	// Simplified check for domain within bailiwick
	out := false
	for _, b := range bailiwick {
		if strings.HasSuffix(domain, b) || domain == b {
			out = true
		}
	}
	return out
}

// IsWithinBailiwick checks if a domain is within the bailiwick of a specified domain
func isWithinBailiwickAuth(domain string, bailiwick []string, qname string) bool {
	// Simplified check for domain within bailiwick
	out := false
	for _, b := range bailiwick {
		if strings.HasSuffix(b, domain) || domain == b || strings.HasSuffix(qname, b) {
			out = true
		}
	}
	return out
}
