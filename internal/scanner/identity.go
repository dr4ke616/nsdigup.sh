package scanner

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"checks/pkg/models"
)

type IdentityScanner struct{}

func NewIdentityScanner() *IdentityScanner {
	return &IdentityScanner{}
}

func (i *IdentityScanner) ScanIdentity(ctx context.Context, domain string) (*models.Identity, error) {
	identity := &models.Identity{
		Registrar:   "",
		Owner:       "",
		ExpiresDays: 0,
	}

	resolver := &net.Resolver{}

	// Channels for parallel checks
	ipsChan := make(chan []net.IP, 1)
	nsChan := make(chan []*net.NS, 1)
	dnssecChan := make(chan DNSSECResult, 1)
	caaChan := make(chan CAAResult, 1)
	whoisChan := make(chan WHOISResult, 1)
	errChan := make(chan error, 2)

	// IP lookup
	go func() {
		ips, err := resolver.LookupIPAddr(ctx, domain)
		if err != nil {
			errChan <- fmt.Errorf("IP lookup failed: %w", err)
			return
		}
		var ipList []net.IP
		for _, ip := range ips {
			ipList = append(ipList, ip.IP)
		}
		ipsChan <- ipList
	}()

	// Nameserver lookup
	go func() {
		ns, err := resolver.LookupNS(ctx, domain)
		if err != nil {
			errChan <- fmt.Errorf("NS lookup failed: %w", err)
			return
		}
		nsChan <- ns
	}()

	// DNSSEC validation
	go func() {
		result := CheckDNSSEC(ctx, domain)
		dnssecChan <- result
	}()

	// CAA records
	go func() {
		result := CheckCAA(ctx, domain)
		caaChan <- result
	}()

	// WHOIS lookup
	go func() {
		result := CheckWHOIS(ctx, domain)
		whoisChan <- result
	}()

	timeout := time.NewTimer(10 * time.Second)
	defer timeout.Stop()

	var ips []net.IP
	var ns []*net.NS
	var dnssecResult DNSSECResult
	var caaResult CAAResult
	var whoisResult WHOISResult
	errors := []error{}

	// Wait for all 5 checks to complete
	for i := 0; i < 5; i++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timeout.C:
			return nil, fmt.Errorf("identity scan timeout")
		case ipList := <-ipsChan:
			ips = ipList
		case nsList := <-nsChan:
			ns = nsList
		case dnssec := <-dnssecChan:
			dnssecResult = dnssec
		case caa := <-caaChan:
			caaResult = caa
		case whois := <-whoisChan:
			whoisResult = whois
		case err := <-errChan:
			errors = append(errors, err)
		}
	}

	// Process IP addresses
	if len(ips) > 0 {
		for _, ip := range ips {
			if ip.To4() != nil {
				identity.IP = ip.String()
				break
			}
		}
		if identity.IP == "" && len(ips) > 0 {
			identity.IP = ips[0].String()
		}
	}

	// Process nameservers
	if len(ns) > 0 {
		identity.Nameservers = make([]string, 0, len(ns))
		for _, n := range ns {
			nsHost := strings.TrimSuffix(n.Host, ".")
			identity.Nameservers = append(identity.Nameservers, nsHost)
		}
	}

	// Process DNSSEC results
	identity.DNSSECEnabled = dnssecResult.Enabled
	identity.DNSSECValid = dnssecResult.Valid
	identity.DNSSECError = dnssecResult.Error

	// Process CAA results
	identity.CAARecords = caaResult.Records
	identity.CAAMissing = caaResult.Missing

	// Process WHOIS results
	if whoisResult.Error == nil {
		identity.Registrar = whoisResult.Registrar
		identity.Owner = whoisResult.Owner
		identity.ExpiresDays = whoisResult.ExpiresDays
	}

	if identity.IP == "" && len(errors) > 0 {
		return identity, fmt.Errorf("DNS resolution failed: %v", errors)
	}

	return identity, nil
}
