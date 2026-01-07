package tools

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"

	"nsdigup/internal/logger"
	"nsdigup/pkg/models"
)

// CheckEmailSecurity analyzes SPF and DMARC records for the given domain.
// It identifies weak or missing email security configurations that could
// allow email spoofing or phishing attacks.
func CheckEmailSecurity(ctx context.Context, domain string) (models.EmailSec, error) {
	emailSec := models.EmailSec{}

	resolver := &net.Resolver{}

	spfRecords, _ := resolver.LookupTXT(ctx, domain)
	for _, txt := range spfRecords {
		if strings.HasPrefix(txt, "v=spf1") {
			emailSec.SPF = txt
			if strings.Contains(txt, "+all") || strings.Contains(txt, "?all") {
				emailSec.IsWeak = true
			}
			break
		}
	}

	dmarcRecords, _ := resolver.LookupTXT(ctx, fmt.Sprintf("_dmarc.%s", domain))
	for _, txt := range dmarcRecords {
		if strings.HasPrefix(txt, "v=DMARC1") {
			if strings.Contains(txt, "p=none") {
				emailSec.DMARC = "none"
				emailSec.IsWeak = true
			} else if strings.Contains(txt, "p=quarantine") {
				emailSec.DMARC = "quarantine"
			} else if strings.Contains(txt, "p=reject") {
				emailSec.DMARC = "reject"
			}
			break
		}
	}

	if emailSec.SPF == "" {
		emailSec.IsWeak = true
		logger.GetFromContext(ctx, logger.Get()).Debug("SPF record missing",
			slog.String("domain", domain))
	}
	if emailSec.DMARC == "" || emailSec.DMARC == "none" {
		if emailSec.DMARC == "" {
			emailSec.DMARC = "none"
		}
		emailSec.IsWeak = true
		logger.GetFromContext(ctx, logger.Get()).Debug("weak DMARC policy",
			slog.String("domain", domain),
			slog.String("policy", emailSec.DMARC))
	}

	return emailSec, nil
}
