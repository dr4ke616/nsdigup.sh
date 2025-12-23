package scanner

import (
	"context"
	"sync"
	"time"

	"checks/pkg/models"
)

type Scanner interface {
	Scan(ctx context.Context, domain string) (*models.Report, error)
}

type Orchestrator struct {
	dns    *DNSScanner
	ssl    *SSLScanner
	config *ConfigScanner
}

func NewOrchestrator() *Orchestrator {
	return &Orchestrator{
		dns:    NewDNSScanner(),
		ssl:    NewSSLScanner(),
		config: NewConfigScanner(),
	}
}

func (o *Orchestrator) Scan(ctx context.Context, domain string) (*models.Report, error) {
	report := &models.Report{
		Target:    domain,
		Timestamp: time.Now(),
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	errors := make([]error, 0)

	wg.Add(3)

	go func() {
		defer wg.Done()
		identity, err := o.dns.ScanIdentity(ctx, domain)
		mu.Lock()
		if err != nil {
			errors = append(errors, err)
		}
		if identity != nil {
			report.Identity = *identity
		}
		mu.Unlock()
	}()

	go func() {
		defer wg.Done()
		certData, err := o.ssl.ScanCertificates(ctx, domain)
		mu.Lock()
		if err != nil {
			errors = append(errors, err)
		}
		if certData != nil {
			report.Certificates = *certData
		}
		mu.Unlock()
	}()

	go func() {
		defer wg.Done()
		misconfigs, err := o.config.ScanMisconfigurations(ctx, domain)
		mu.Lock()
		if err != nil {
			errors = append(errors, err)
		}
		if misconfigs != nil {
			report.Misconfigurations = *misconfigs
		}
		mu.Unlock()
	}()

	wg.Wait()

	if len(errors) > 0 && report.Identity.IP == "" && report.Certificates.Current.CommonName == "" {
		return report, errors[0]
	}

	return report, nil
}
