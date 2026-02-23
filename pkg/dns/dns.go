package dns

import (
	"context"
	"fmt"
	"strings"

	"github.com/projectdiscovery/dnsx/libs/dnsx"
)

// Client is a wrapper around dnsx's client
type Client struct {
	dnsx *dnsx.DNSX
}

// NewClient creates a new dnsx client
func NewClient(resolvers []string, threads int) (*Client, error) {
	options := dnsx.DefaultOptions
	if len(resolvers) > 0 {
		options.BaseResolvers = resolvers
	}

	dnsxClient, err := dnsx.New(options)
	if err != nil {
		return nil, err
	}

	return &Client{
		dnsx: dnsxClient,
	}, nil
}

// Resolve resolves a list of domains and returns only the resolved ones
func (c *Client) Resolve(ctx context.Context, domains []string) ([]string, error) {
	var resolved []string

	for _, domain := range domains {
		result, err := c.dnsx.QueryOne(domain)
		if err != nil {
			continue
		}
		if result != nil && (len(result.A) > 0 || len(result.AAAA) > 0 || len(result.CNAME) > 0) {
			resolved = append(resolved, domain)
		}
	}

	return resolved, nil
}

// Bruteforce performs DNS bruteforcing for a domain using a wordlist
func (c *Client) Bruteforce(ctx context.Context, domain string, wordlist []string) ([]string, error) {
	var discovered []string

	for _, word := range wordlist {
		subdomain := fmt.Sprintf("%s.%s", strings.TrimSpace(word), domain)
		result, err := c.dnsx.QueryOne(subdomain)
		if err != nil {
			continue
		}
		if result != nil && (len(result.A) > 0 || len(result.AAAA) > 0 || len(result.CNAME) > 0) {
			discovered = append(discovered, subdomain)
		}
	}

	return discovered, nil
}
