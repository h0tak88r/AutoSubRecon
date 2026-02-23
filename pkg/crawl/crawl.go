package crawl

import (
	"context"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Scraper is a simple JS/HTML scraper for subdomains
type Scraper struct {
	client *http.Client
}

// NewScraper creates a new scraper
func NewScraper() *Scraper {
	return &Scraper{
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Extract extracts subdomains from a URL
func (s *Scraper) Extract(ctx context.Context, url, domain string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (AutoSubRecon)")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Simple regex for subdomains
	re := regexp.MustCompile(`([a-zA-Z0-9.-]+\.` + regexp.QuoteMeta(domain) + `)`)
	matches := re.FindAllString(string(body), -1)

	subdomains := make(map[string]bool)
	for _, m := range matches {
		m = strings.ToLower(strings.Trim(m, "."))
		if strings.HasSuffix(m, "."+domain) || m == domain {
			subdomains[m] = true
		}
	}

	var results []string
	for k := range subdomains {
		results = append(results, k)
	}

	return results, nil
}
