package scanner

import (
	"context"
	"fmt"
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

	// Channels for parallel checks
	ipsChan := make(chan string, 1)
	nsChan := make(chan []string, 1)
	dnssecChan := make(chan DNSSECResult, 1)
	caaChan := make(chan CAAResult, 1)
	whoisChan := make(chan WHOISResult, 1)
	errChan := make(chan error, 2)

	// IP lookup
	go func() {
		ip, err := GetIPAddress(ctx, domain)
		if err != nil {
			errChan <- err
			return
		}
		ipsChan <- ip
	}()

	// Nameserver lookup
	go func() {
		nameservers, err := GetNameservers(ctx, domain)
		if err != nil {
			errChan <- err
			return
		}
		nsChan <- nameservers
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

	var ip string
	var nameservers []string
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
		case ipAddr := <-ipsChan:
			ip = ipAddr
		case ns := <-nsChan:
			nameservers = ns
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

	// Set IP and nameservers
	identity.IP = ip
	identity.Nameservers = nameservers

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
