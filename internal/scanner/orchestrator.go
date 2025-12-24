package scanner

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"checks/internal/logger"
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
	log := logger.Get()
	log.Debug("starting concurrent domain scan", slog.String("domain", domain))

	report := &models.Report{
		Target:    domain,
		Timestamp: time.Now(),
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	errors := make([]error, 0)

	wg.Add(3)

	// DNS scan
	go func() {
		defer wg.Done()
		start := time.Now()
		identity, err := o.dns.ScanIdentity(ctx, domain)
		duration := time.Since(start)

		mu.Lock()
		if err != nil {
			log.Warn("DNS scan failed",
				slog.String("domain", domain),
				slog.String("error", err.Error()),
				slog.Duration("duration", duration))
			errors = append(errors, err)
		} else if identity != nil {
			log.Debug("DNS scan completed",
				slog.String("domain", domain),
				slog.Duration("duration", duration),
				slog.String("ip", identity.IP))
		}
		if identity != nil {
			report.Identity = *identity
		}
		mu.Unlock()
	}()

	// SSL scan
	go func() {
		defer wg.Done()
		start := time.Now()
		certData, err := o.ssl.ScanCertificates(ctx, domain)
		duration := time.Since(start)

		mu.Lock()
		if err != nil {
			log.Warn("SSL scan failed",
				slog.String("domain", domain),
				slog.String("error", err.Error()),
				slog.Duration("duration", duration))
			errors = append(errors, err)
		} else if certData != nil {
			log.Debug("SSL scan completed",
				slog.String("domain", domain),
				slog.Duration("duration", duration),
				slog.String("issuer", certData.Current.Issuer))
		}
		if certData != nil {
			report.Certificates = *certData
		}
		mu.Unlock()
	}()

	// Config scan
	go func() {
		defer wg.Done()
		start := time.Now()
		misconfigs, err := o.config.ScanMisconfigurations(ctx, domain)
		duration := time.Since(start)

		mu.Lock()
		if err != nil {
			log.Warn("config scan failed",
				slog.String("domain", domain),
				slog.String("error", err.Error()),
				slog.Duration("duration", duration))
			errors = append(errors, err)
		} else if misconfigs != nil {
			log.Debug("config scan completed",
				slog.String("domain", domain),
				slog.Duration("duration", duration),
				slog.Int("header_issues", len(misconfigs.Headers)))
		}
		if misconfigs != nil {
			report.Misconfigurations = *misconfigs
		}
		mu.Unlock()
	}()

	wg.Wait()

	// Check if complete failure (no results from any scanner)
	if len(errors) > 0 && report.Identity.IP == "" && report.Certificates.Current.CommonName == "" {
		log.Error("complete scan failure",
			slog.String("domain", domain),
			slog.Int("error_count", len(errors)))
		return report, errors[0]
	}

	// Log partial success
	if len(errors) > 0 {
		log.Info("partial scan success",
			slog.String("domain", domain),
			slog.Int("failures", len(errors)))
	}

	return report, nil
}
