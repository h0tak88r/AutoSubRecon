package http

import (
	"context"

	"github.com/projectdiscovery/httpx/common/httpx"
)

// Client is a wrapper around httpx's client
type Client struct {
	httpx *httpx.HTTPX
}

// NewClient creates a new httpx client
func NewClient(threads int) (*Client, error) {
	options := httpx.DefaultOptions
	options.Threads = threads
	options.Timeout = 10

	httpxClient, err := httpx.New(&options)
	if err != nil {
		return nil, err
	}

	return &Client{
		httpx: httpxClient,
	}, nil
}

// CheckLive checks which of the provided domains are live web hosts
func (c *Client) CheckLive(ctx context.Context, domains []string) ([]string, error) {
	var live []string

	for _, domain := range domains {
		// Try both http and https
		for _, protocol := range []string{"http", "https"} {
			url := protocol + "://" + domain
			req, err := c.httpx.NewRequest("GET", url)
			if err != nil {
				continue
			}
			result, err := c.httpx.Do(req, httpx.UnsafeOptions{})
			if err == nil && result != nil {
				live = append(live, url)
				break // If one protocol works, we consider it live
			}
		}
	}

	return live, nil
}

