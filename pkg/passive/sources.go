package passive

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// SecurityTrailsSource implements a custom source for SecurityTrails
type SecurityTrailsSource struct {
	apiKey string
	client *http.Client
}

// NewSecurityTrailsSource creates a new SecurityTrails source
func NewSecurityTrailsSource(apiKey string) *SecurityTrailsSource {
	return &SecurityTrailsSource{
		apiKey: apiKey,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

type securityTrailsResponse struct {
	Subdomains []string `json:"subdomains"`
}

// Enumerate fetches subdomains from SecurityTrails
func (s *SecurityTrailsSource) Enumerate(ctx context.Context, domain string) ([]string, error) {
	url := fmt.Sprintf("https://api.securitytrails.com/v1/domain/%s/subdomains?children_only=false", domain)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("accept", "application/json")
	req.Header.Set("apikey", s.apiKey)

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("securitytrails returned status %d", resp.StatusCode)
	}

	var stResp securityTrailsResponse
	if err := json.NewDecoder(resp.Body).Decode(&stResp); err != nil {
		return nil, err
	}

	var results []string
	for _, sub := range stResp.Subdomains {
		results = append(results, fmt.Sprintf("%s.%s", sub, domain))
	}

	return results, nil
}

// FacebookSource (Placeholder or implementation if needed)
// Subfinder already has a good facebook source if API keys are provided.
