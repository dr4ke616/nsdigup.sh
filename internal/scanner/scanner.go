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

type ScannerImpl struct {
	identity    *IdentityScanner
	certificate *CertificateScanner
	findings    *FindingsScanner
}

func NewScanner() *ScannerImpl {
	defaultTimeout := 10 * time.Second

	return &ScannerImpl{
		identity:    NewIdentityScanner(defaultTimeout),
		certificate: NewCertificateScanner(defaultTimeout),
		findings:    NewFindingsScanner(defaultTimeout),
	}
}

func (o *ScannerImpl) Scan(ctx context.Context, domain string) (*models.Report, error) {
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

	// Identity scan
	go func() {
		defer wg.Done()
		start := time.Now()
		identity, err := o.identity.ScanIdentity(ctx, domain)
		duration := time.Since(start)

		mu.Lock()
		if err != nil {
			log.Warn("identity scan failed",
				slog.String("domain", domain),
				slog.String("error", err.Error()),
				slog.Duration("duration", duration))
			errors = append(errors, err)
		} else if identity != nil {
			log.Debug("identity scan completed",
				slog.String("domain", domain),
				slog.Duration("duration", duration),
				slog.String("ip", identity.IP))
		}
		if identity != nil {
			report.Identity = *identity
		}
		mu.Unlock()
	}()

	// Certificate scan
	go func() {
		defer wg.Done()
		start := time.Now()
		certData, err := o.certificate.ScanCertificates(ctx, domain)
		duration := time.Since(start)

		mu.Lock()
		if err != nil {
			log.Warn("certificate scan failed",
				slog.String("domain", domain),
				slog.String("error", err.Error()),
				slog.Duration("duration", duration))
			errors = append(errors, err)
		} else if certData != nil {
			log.Debug("certificate scan completed",
				slog.String("domain", domain),
				slog.Duration("duration", duration),
				slog.String("issuer", certData.Issuer))
		}
		if certData != nil {
			report.Certificates = *certData
		}
		mu.Unlock()
	}()

	// Findings scan
	go func() {
		defer wg.Done()
		start := time.Now()
		findings, err := o.findings.ScanFindings(ctx, domain)
		duration := time.Since(start)

		mu.Lock()
		if err != nil {
			log.Warn("findings scan failed",
				slog.String("domain", domain),
				slog.String("error", err.Error()),
				slog.Duration("duration", duration))
			errors = append(errors, err)
		} else if findings != nil {
			log.Debug("findings scan completed",
				slog.String("domain", domain),
				slog.Duration("duration", duration),
				slog.Int("header_issues", len(findings.Headers)))
		}
		if findings != nil {
			report.Findings = *findings
		}
		mu.Unlock()
	}()

	wg.Wait()

	// Check if complete failure (no results from any scanner)
	if len(errors) > 0 && report.Identity.IP == "" && report.Certificates.CommonName == "" {
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
