package tools

import (
	"context"
	"fmt"
	"net"
	"strings"
)

// GetIPAddress retrieves the primary IP address for the given domain.
// It performs a DNS lookup and returns the first IPv4 address found,
// or the first IP address if no IPv4 address is available.
func GetIPAddress(ctx context.Context, domain string) (string, error) {
	resolver := &net.Resolver{}

	ips, err := resolver.LookupIPAddr(ctx, domain)
	if err != nil {
		return "", fmt.Errorf("IP lookup failed: %w", err)
	}

	if len(ips) == 0 {
		return "", fmt.Errorf("no IP addresses found for domain")
	}

	var ipList []net.IP
	for _, ip := range ips {
		ipList = append(ipList, ip.IP)
	}

	// Prefer IPv4 addresses
	for _, ip := range ipList {
		if ip.To4() != nil {
			return ip.String(), nil
		}
	}

	// Fallback to first IP if no IPv4 found
	return ipList[0].String(), nil
}

// GetNameservers retrieves the nameserver records for the given domain.
// It performs a DNS NS lookup and returns a list of nameserver hostnames
// with trailing dots removed.
func GetNameservers(ctx context.Context, domain string) ([]string, error) {
	resolver := &net.Resolver{}

	ns, err := resolver.LookupNS(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("NS lookup failed: %w", err)
	}

	if len(ns) == 0 {
		return []string{}, nil
	}

	nameservers := make([]string, 0, len(ns))
	for _, n := range ns {
		nsHost := strings.TrimSuffix(n.Host, ".")
		nameservers = append(nameservers, nsHost)
	}

	return nameservers, nil
}
