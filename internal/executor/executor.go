package executor

import (
	"bufio"
	"fmt"
	"os"

	"github.com/logrusorgru/aurora"
	"github.com/m-1tZ/dnstake2/internal/errors"
	"github.com/m-1tZ/dnstake2/internal/option"
	"github.com/m-1tZ/dnstake2/pkg/dnstake"
	"github.com/m-1tZ/dnstake2/pkg/fingerprint"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/retryabledns"
)

// New to execute target hostname
func New(opt *option.Options, hostname string) {
	var out = ""

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

	fmt.Println(q1)

	if len(q1.NS) < 1 {
		return vuln, DNS, fmt.Errorf("%s", errors.ErrNoNSRec)
	}

	// TODO check base domain from ns servers
	// baseDomain()
	// for _, ns := range q1.NS {
	// 	apexDomain(ns)

	// }

	// TODO, only checks if one regex matches, if so then returns vulnerable status like awsdns but nsone could also be serving
	// checks if NS servers are in the vulnerable list
	fgp, rec, err := fingerprint.Check(q1.NS)
	if err != nil {
		return vuln, fgp, fmt.Errorf("%s (%s)", errors.ErrPattern, err.Error())
	}

	if rec == "" {
		return false, fgp, fmt.Errorf("%s", errors.ErrFinger)
	}

	// checks if ns server is likely to be vulnerable
	if _, m := find(fgp.Status, 0); m {
		return vuln, DNS, fmt.Errorf("%s", errors.ErrNotVuln)
	}

	// resolves ns nameservers
	q2, err := dnstake.Resolve(client, rec, 1)
	if err != nil {
		return vuln, DNS, fmt.Errorf("%s (%s)", errors.ErrResolve, rec)
	}

	// checks host against each ns record for weird status
	vuln, err = dnstake.Verify(q2.A, hostname)
	if err != nil {
		return vuln, DNS, fmt.Errorf("%s (%s)", errors.ErrVerify, err.Error())
	}

	if vuln {
		return vuln, fgp, nil
	}

	return false, fgp, fmt.Errorf("%s", errors.ErrUnknown)
}
