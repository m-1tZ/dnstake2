package fingerprint

import "regexp"

// Check do fingerprinting
// Could be vuln and not
// nsone.net
// awsdns-21.com
// TODO: return both states 1 and 0 in this case
func Check(NS []string) (DNS, []string, error) {
	vulnerables := []string{}
	fingerprint := DNS{}
	for _, f := range Get() {
		for _, r := range NS {

			m, e := regexp.MatchString(f.Pattern, r)
			if e != nil {
				return DNS{}, nil, e
			}
			if m {
				vulnerables = append(vulnerables, r)
				fingerprint = f
			}
		}
	}
	return fingerprint, vulnerables, nil
}
