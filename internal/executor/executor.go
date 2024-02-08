package executor

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/logrusorgru/aurora"
	"github.com/m-1tZ/dnstake2/internal/errors"
	"github.com/m-1tZ/dnstake2/internal/option"
	"github.com/m-1tZ/dnstake2/pkg/dnstake"
	"github.com/m-1tZ/dnstake2/pkg/fingerprint"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/retryabledns"
)

var (
	opts *option.Options
	db   *sql.DB
	err  error
)

// New to execute target hostname
func New(opt *option.Options, hostname string) {
	var out = ""
	// globally available in package
	opts = opt

	// setup db for dedupe apex domains
	db, err = createOrOpenDB("/tmp/checked_domains.db")
	if err != nil {
		gologger.Error().Msgf("%s: %s", "DBcreateError", err.Error())
	}

	vuln, DNS, err := exec(hostname)
	if err != nil {
		gologger.Error().Msgf("%s: %s", hostname, err.Error())
	}

	if vuln {
		if !opt.Silent {
			out += fmt.Sprintf("[%s] ", aurora.Green("VLN"))
		}

		out += hostname

		if !opt.Silent {
			out += fmt.Sprintf(" (%s)", aurora.Cyan(DNS.Provider))
		}

		if !opt.Silent {
			for _, status := range DNS.Status {
				switch status {
				case 2:
					out += fmt.Sprintf(" (%s)", aurora.Magenta("Edge Case"))
				case 3:
					out += fmt.Sprintf(" (%s)", aurora.Yellow("$"))
				}
			}
		}

		if opt.Output != "" {
			writeToFile(hostname, opt.Output)
		}
	}

	if out != "" {
		fmt.Println(out)
	}
}

func writeToFile(data, output string) {
	mu.Lock()
	defer mu.Unlock()

	file, err := os.OpenFile(output, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		gologger.Fatal().Msg(err.Error())
	}

	wrt := bufio.NewWriter(file)

	_, err = wrt.WriteString(data + "\n")
	if err != nil {
		gologger.Error().Msg(err.Error())
	}

	wrt.Flush()
	file.Close()
}

// Main Logic
func exec(hostname string) (bool, fingerprint.DNS, error) {
	var (
		vuln bool
		DNS  = fingerprint.DNS{}
	)

	client, err := retryabledns.New([]string{"8.8.8.8:53", "1.1.1.1:53", "8.8.4.4:53", "9.9.9.9:53", "149.112.112.112:53", "208.67.222.222:53", "208.67.220.220:53"}, 3)
	if err != nil {
		return false, fingerprint.DNS{}, err
	}

	// dns resolve
	q1, err := dnstake.Resolve(client, hostname, 2)
	if err != nil {
		return vuln, DNS, fmt.Errorf("%s", errors.ErrResolve)
	}

	// Check if CNAME, if so then use this value for checks
	if len(q1.CNAME) > 0 {
		hostname = q1.CNAME[0]
		// Multiple CNAMEs
		if len(q1.CNAME) > 1 {
			// take the last of the CNAMEs
			hostname = q1.CNAME[len(q1.CNAME)-1]
		}

		q1, err = dnstake.Resolve(client, hostname, 2)
		if err != nil {
			return vuln, DNS, fmt.Errorf("%s", errors.ErrResolve)
		}
	}

	if len(q1.NS) < 1 {
		return vuln, DNS, fmt.Errorf("%s", errors.ErrNoNSRec)
	}

	// check base domain from ns servers that are not in the list
	if opts.GandiApiKey != "" {
		matched, matchedDomain, err := domainAvailable(q1.NS)
		if err != nil {
			gologger.Error().Msgf("Error in domain availability check: %s", err)
		}
		if matched {
			return vuln, fingerprint.DNS{Provider: matchedDomain, Status: []int{1}, Pattern: "apex domain available"}, nil
		}
	}

	// checks if NS servers are in the vulnerable list
	fgp, recs, err := fingerprint.Check(q1.NS)
	if err != nil {
		return vuln, fgp, fmt.Errorf("%s (%s)", errors.ErrPattern, err.Error())
	}

	if len(recs) == 0 {
		return false, fgp, fmt.Errorf("%s", errors.ErrFinger)
	}

	// checks if ns server is likely to be vulnerable
	if _, m := find(fgp.Status, 1); !m {
		return vuln, DNS, fmt.Errorf("%s", errors.ErrNotVuln)
	}

	// Check domain against each NS server
	for _, rec := range recs {
		q2, err := dnstake.Resolve(client, rec, 1)
		if err != nil {
			return vuln, DNS, fmt.Errorf("%s (%s)", errors.ErrResolve, rec)
		}
		// checks host against each IP of ns record for weird status
		vuln, err = dnstake.Verify(q2.A, hostname)
		if err != nil {
			return vuln, DNS, fmt.Errorf("%s (%s)", errors.ErrVerify, err.Error())
		}

		if vuln {
			return vuln, fgp, nil
		}
	}

	return false, fingerprint.DNS{}, nil
}

func domainAvailable(domains []string) (bool, string, error) {
	var dedupedDomains []string

	for _, domain := range domains {
		apDomain := apexDomain(domain)
		checked, err := isDomainChecked(db, apDomain)
		if err != nil {
			return false, "", err
		}
		if !checked {
			dedupedDomains = append(dedupedDomains, apDomain)
		}
	}

	for _, domain := range dedupedDomains {
		// Gandi.net API endpoint for domain availability check
		apiEndpoint := fmt.Sprintf("https://api.gandi.net/v5/domain/check?name=%s", domain)
		// Create an HTTP client
		client := &http.Client{}

		// Create a request with the Gandi.net API key
		req, err := http.NewRequest("GET", apiEndpoint, nil)
		if err != nil {
			return false, "", err
		}
		req.Header.Set("Authorization", "Bearer "+opts.GandiApiKey)

		// Make the API request
		resp, err := client.Do(req)
		if err != nil {
			return false, "", err
		}
		defer resp.Body.Close()

		// Read the response body
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return false, "", err
		}

		// Check if the domain is available
		if resp.StatusCode == http.StatusOK {
			var response DomainAvailabilityResponse
			err := json.Unmarshal(body, &response)
			if err != nil {
				return false, "", err
			}

			// Assuming there is only one product in the response
			if len(response.Products) > 0 {
				// apex domain is available!!!
				if response.Products[0].Status == "available" {
					return true, domain, nil
				}
			}
		} else {
			gologger.Error().Msgf("%s: Gandi: %s - either got into rate limit or connectivity issues", domain, strconv.Itoa(resp.StatusCode))
			time.Sleep(60 * time.Second)
		}

	}
	return false, "", nil
}
