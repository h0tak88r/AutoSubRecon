package passive

import (
	"bytes"
	"context"
	"io"
	"os"
	"strings"

	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

// Runner is a wrapper around subfinder's runner
type Runner struct {
	subfinder *runner.Runner
}

// NewRunner creates a new subfinder runner
func NewRunner(threads int) (*Runner, error) {
	options := &runner.Options{
		Threads:            threads,
		Timeout:            30,
		MaxEnumerationTime: 10,
	}

	subfinderRunner, err := runner.NewRunner(options)
	if err != nil {
		return nil, err
	}

	return &Runner{
		subfinder: subfinderRunner,
	}, nil
}

// Enumerate performs passive subdomain enumeration for a domain
func (r *Runner) Enumerate(ctx context.Context, domain string) ([]string, error) {
	var allSubs []string

	// 1. Subfinder
	output := &bytes.Buffer{}
	_, err := r.subfinder.EnumerateSingleDomain(domain, []io.Writer{output})
	if err == nil {
		scanner := bytes.NewBuffer(output.Bytes())
		for {
			line, err := scanner.ReadString('\n')
			if err != nil {
				if err == io.EOF {
					break
				}
				break
			}
			allSubs = append(allSubs, strings.TrimSpace(line))
		}
	}

	// 2. SecurityTrails (Custom)
	apiKey := os.Getenv("SECURITYTRAILS_API_KEY")
	
	if apiKey != "" {
		st := NewSecurityTrailsSource(apiKey)
		subs, err := st.Enumerate(ctx, domain)
		if err == nil {
			allSubs = append(allSubs, subs...)
		}
	}

	return allSubs, nil
}


