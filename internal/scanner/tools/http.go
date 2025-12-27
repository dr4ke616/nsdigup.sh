package tools

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// RedirectResult contains the results of HTTP to HTTPS redirect checking
type RedirectResult struct {
	Enabled      bool
	StatusCode   int
	FinalURL     string
	RedirectLoop bool
	Error        string
}

// CheckHTTPSRedirect tests if HTTP properly redirects to HTTPS
func CheckHTTPSRedirect(ctx context.Context, domain string, timeout time.Duration) RedirectResult {
	result := RedirectResult{
		Enabled: false,
	}

	domain = normalizeDomain(domain)

	// Build HTTP URL (non-secure)
	httpURL := fmt.Sprintf("http://%s", domain)

	// Create HTTP client that doesn't follow redirects automatically
	// We want to inspect each redirect manually
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Don't follow redirects, we'll do it manually
			return http.ErrUseLastResponse
		},
	}

	// Track visited URLs to detect loops
	visited := make(map[string]bool)
	currentURL := httpURL
	maxRedirects := 10

	for i := 0; i < maxRedirects; i++ {
		// Check for redirect loop
		if visited[currentURL] {
			result.RedirectLoop = true
			result.Error = "redirect loop detected"
			return result
		}
		visited[currentURL] = true

		// Make request
		req, err := http.NewRequestWithContext(ctx, "GET", currentURL, nil)
		if err != nil {
			result.Error = fmt.Sprintf("request creation failed: %v", err)
			return result
		}

		// Set user agent
		req.Header.Set("User-Agent", "nsdigup.sh/1.0 (Security Scanner)")

		resp, err := client.Do(req)
		if err != nil {
			result.Error = fmt.Sprintf("request failed: %v", err)
			return result
		}

		result.StatusCode = resp.StatusCode

		// Check if this is a redirect (3xx status code)
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			// Get redirect location
			location := resp.Header.Get("Location")
			if location == "" {
				result.Error = "redirect without Location header"
				resp.Body.Close()
				return result
			}

			// Parse redirect URL
			redirectURL, err := url.Parse(location)
			if err != nil {
				result.Error = fmt.Sprintf("invalid redirect URL: %v", err)
				resp.Body.Close()
				return result
			}

			// Handle relative URLs
			if !redirectURL.IsAbs() {
				baseURL, _ := url.Parse(currentURL)
				redirectURL = baseURL.ResolveReference(redirectURL)
			}

			// Check if we've reached HTTPS
			if redirectURL.Scheme == "https" {
				result.Enabled = true
				result.FinalURL = redirectURL.String()
				resp.Body.Close()
				return result
			}

			// Continue following redirect chain
			currentURL = redirectURL.String()
			resp.Body.Close()
			continue
		}

		// Not a redirect - check if we're already on HTTPS
		finalURLParsed, _ := url.Parse(currentURL)
		if finalURLParsed.Scheme == "https" {
			result.Enabled = true
			result.FinalURL = currentURL
		} else {
			result.Enabled = false
			result.Error = "no HTTPS redirect found"
		}

		resp.Body.Close()
		return result
	}

	// Exceeded max redirects
	result.Error = fmt.Sprintf("exceeded maximum redirects (%d)", maxRedirects)
	return result
}

// CheckSecurityHeaders performs an HTTP request to the domain and checks for
// security-related HTTP headers (HSTS, CSP, X-Frame-Options, etc.).
// Returns a list of security issues found.
func CheckHttpSecurityHeaders(ctx context.Context, domain string, timeout time.Duration) ([]string, error) {
	issues := []string{}

	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	req, err := http.NewRequestWithContext(ctx, "HEAD", fmt.Sprintf("https://%s", domain), nil)
	if err != nil {
		return issues, err
	}

	resp, err := client.Do(req)
	if err != nil {
		req.URL.Scheme = "http"
		resp, err = client.Do(req)
		if err != nil {
			return issues, fmt.Errorf("HTTP request failed: %w", err)
		}
	}
	defer resp.Body.Close()

	if resp.Header.Get("Strict-Transport-Security") == "" {
		issues = append(issues, "Missing HSTS header")
	}

	csp := resp.Header.Get("Content-Security-Policy")
	if csp == "" {
		issues = append(issues, "Missing CSP header")
	} else if strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "unsafe-eval") {
		issues = append(issues, "Weak CSP policy (contains unsafe-inline or unsafe-eval)")
	}

	if resp.Header.Get("X-Frame-Options") == "" && !strings.Contains(csp, "frame-ancestors") {
		issues = append(issues, "Missing X-Frame-Options header")
	}

	if resp.Header.Get("X-Content-Type-Options") == "" {
		issues = append(issues, "Missing X-Content-Type-Options header")
	}

	if resp.Header.Get("Referrer-Policy") == "" {
		issues = append(issues, "Missing Referrer-Policy header")
	}

	permissionsPolicy := resp.Header.Get("Permissions-Policy")
	if permissionsPolicy == "" {
		permissionsPolicy = resp.Header.Get("Feature-Policy")
	}
	if permissionsPolicy == "" {
		issues = append(issues, "Missing Permissions-Policy header")
	}

	return issues, nil
}

// isHTTPS checks if a URL uses HTTPS scheme
func isHTTPS(urlStr string) bool {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return false
	}
	return strings.ToLower(parsed.Scheme) == "https"
}
