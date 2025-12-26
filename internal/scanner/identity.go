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

	ipsChan := make(chan []net.IP, 1)
	nsChan := make(chan []*net.NS, 1)
	errChan := make(chan error, 2)

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

	go func() {
		ns, err := resolver.LookupNS(ctx, domain)
		if err != nil {
			errChan <- fmt.Errorf("NS lookup failed: %w", err)
			return
		}
		nsChan <- ns
	}()

	timeout := time.NewTimer(5 * time.Second)
	defer timeout.Stop()

	var ips []net.IP
	var ns []*net.NS
	errors := []error{}

	for i := 0; i < 2; i++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timeout.C:
			return nil, fmt.Errorf("DNS scan timeout")
		case ipList := <-ipsChan:
			ips = ipList
		case nsList := <-nsChan:
			ns = nsList
		case err := <-errChan:
			errors = append(errors, err)
		}
	}

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

	if len(ns) > 0 {
		identity.Nameservers = make([]string, 0, len(ns))
		for _, n := range ns {
			nsHost := strings.TrimSuffix(n.Host, ".")
			identity.Nameservers = append(identity.Nameservers, nsHost)
		}
	}

	if identity.IP == "" && len(errors) > 0 {
		return identity, fmt.Errorf("DNS resolution failed: %v", errors)
	}

	return identity, nil
}
