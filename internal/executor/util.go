package executor

import (
	parser "github.com/Cgboal/DomainParser"
)

func find(slice []int, val int) (int, bool) {
	for i, item := range slice {
		if item == val {
			return i, true
		}
	}

	return -1, false
}

func apexDomain(domain string) string {
	extractor := parser.NewDomainParser()

	apex := extractor.GetDomain(domain) + "." + extractor.GetTld(domain)

	return apex
}

func domainAvailable() {

}
