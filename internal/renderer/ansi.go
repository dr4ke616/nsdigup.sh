package renderer

import (
	"fmt"
	"io"
	"strings"
	"time"

	"checks/pkg/models"
)

type Renderer interface {
	Render(w io.Writer, report *models.Report) error
}

type ANSIRenderer struct{}

func NewANSIRenderer() *ANSIRenderer {
	return &ANSIRenderer{}
}

// ANSI color codes
const (
	Reset     = "\033[0m"
	Bold      = "\033[1m"
	Dim       = "\033[2m"
	Red       = "\033[31m"
	Green     = "\033[32m"
	Yellow    = "\033[33m"
	Blue      = "\033[34m"
	Magenta   = "\033[35m"
	Cyan      = "\033[36m"
	White     = "\033[37m"
	BrightRed = "\033[91m"
)

func (a *ANSIRenderer) Render(w io.Writer, report *models.Report) error {
	if report == nil {
		return fmt.Errorf("report cannot be nil")
	}

	// Header
	fmt.Fprintf(w, "%s%s═══ checks.sh ═══%s\n", Bold, Cyan, Reset)
	fmt.Fprintf(w, "%sTarget:%s %s%s%s\n", Bold, Reset, Green, report.Target, Reset)
	fmt.Fprintf(w, "%sScanned:%s %s\n\n", Dim, Reset, report.Timestamp.Format("2006-01-02 15:04:05 UTC"))

	// Identity section
	if err := a.renderIdentity(w, &report.Identity); err != nil {
		return err
	}

	// Certificates section
	if err := a.renderCertificates(w, &report.Certificates); err != nil {
		return err
	}

	// Misconfigurations section
	if err := a.renderMisconfigurations(w, &report.Misconfigurations); err != nil {
		return err
	}

	return nil
}

func (a *ANSIRenderer) renderIdentity(w io.Writer, identity *models.Identity) error {
	fmt.Fprintf(w, "%s%s[ IDENTITY ]%s\n", Bold, Blue, Reset)

	if identity.IP != "" {
		fmt.Fprintf(w, "  %sIP Address:%s %s\n", Bold, Reset, identity.IP)
	}

	if len(identity.Nameservers) > 0 {
		fmt.Fprintf(w, "  %sNameservers:%s\n", Bold, Reset)
		for _, ns := range identity.Nameservers {
			fmt.Fprintf(w, "    • %s\n", ns)
		}
	}

	// Only show WHOIS fields if they have values (Phase 2+ features)
	if identity.Registrar != "" {
		fmt.Fprintf(w, "  %sRegistrar:%s %s\n", Bold, Reset, identity.Registrar)
	}

	if identity.Owner != "" {
		fmt.Fprintf(w, "  %sOwner:%s %s\n", Bold, Reset, identity.Owner)
	}

	if identity.ExpiresDays > 0 {
		color := Green
		if identity.ExpiresDays < 30 {
			color = Red
		} else if identity.ExpiresDays < 90 {
			color = Yellow
		}
		fmt.Fprintf(w, "  %sExpires:%s %s%d days%s\n", Bold, Reset, color, identity.ExpiresDays, Reset)
	}

	fmt.Fprintf(w, "\n")
	return nil
}

func (a *ANSIRenderer) renderCertificates(w io.Writer, certs *models.CertData) error {
	fmt.Fprintf(w, "%s%s[ CERTIFICATES ]%s\n", Bold, Magenta, Reset)

	// Current certificate
	if certs.Current.CommonName != "" {
		fmt.Fprintf(w, "  %sCurrent Certificate:%s\n", Bold, Reset)
		fmt.Fprintf(w, "    %sCommon Name:%s %s", Bold, Reset, certs.Current.CommonName)
		
		if certs.Current.IsWildcard {
			fmt.Fprintf(w, " %s(wildcard)%s", Yellow, Reset)
		}
		fmt.Fprintf(w, "\n")

		if certs.Current.Issuer != "" {
			fmt.Fprintf(w, "    %sIssuer:%s %s\n", Bold, Reset, certs.Current.Issuer)
		}

		// Status with color coding
		statusColor := Green
		if certs.Current.Status == "Expired" {
			statusColor = Red
		} else if certs.Current.Status == "Expiring Soon" {
			statusColor = Yellow
		}
		fmt.Fprintf(w, "    %sStatus:%s %s%s%s\n", Bold, Reset, statusColor, certs.Current.Status, Reset)

		if !certs.Current.NotAfter.IsZero() {
			expiry := certs.Current.NotAfter.Format("2006-01-02")
			daysUntilExpiry := int(time.Until(certs.Current.NotAfter).Hours() / 24)
			
			expiryColor := Green
			if daysUntilExpiry < 0 {
				expiryColor = Red
			} else if daysUntilExpiry < 30 {
				expiryColor = Yellow
			}
			
			fmt.Fprintf(w, "    %sExpires:%s %s%s (%d days)%s\n", Bold, Reset, expiryColor, expiry, daysUntilExpiry, Reset)
		}
	} else {
		fmt.Fprintf(w, "  %sNo certificate information available%s\n", Dim, Reset)
	}

	fmt.Fprintf(w, "\n")
	return nil
}

func (a *ANSIRenderer) renderMisconfigurations(w io.Writer, misconfigs *models.Misconfigurations) error {
	fmt.Fprintf(w, "%s%s[ MISCONFIGURATIONS ]%s\n", Bold, Yellow, Reset)

	hasIssues := false

	// Email security
	if misconfigs.EmailSec.SPF != "" || misconfigs.EmailSec.DMARC != "" {
		fmt.Fprintf(w, "  %sEmail Security:%s\n", Bold, Reset)
		
		if misconfigs.EmailSec.SPF != "" {
			spfColor := Green
			if strings.Contains(misconfigs.EmailSec.SPF, "+all") || strings.Contains(misconfigs.EmailSec.SPF, "?all") {
				spfColor = Red
			}
			fmt.Fprintf(w, "    %sSPF:%s %s%s%s\n", Bold, Reset, spfColor, misconfigs.EmailSec.SPF, Reset)
		}

		if misconfigs.EmailSec.DMARC != "" {
			dmarcColor := Green
			if misconfigs.EmailSec.DMARC == "none" {
				dmarcColor = Red
			} else if misconfigs.EmailSec.DMARC == "quarantine" {
				dmarcColor = Yellow
			}
			fmt.Fprintf(w, "    %sDMARC Policy:%s %s%s%s\n", Bold, Reset, dmarcColor, misconfigs.EmailSec.DMARC, Reset)
		}

		if misconfigs.EmailSec.IsWeak {
			fmt.Fprintf(w, "    %s⚠ Weak email security configuration%s\n", Red, Reset)
		}
		
		hasIssues = true
	}

	// Header issues
	if len(misconfigs.Headers) > 0 {
		if hasIssues {
			fmt.Fprintf(w, "\n")
		}
		fmt.Fprintf(w, "  %sSecurity Headers:%s\n", Bold, Reset)
		for _, issue := range misconfigs.Headers {
			fmt.Fprintf(w, "    %s⚠%s %s\n", Red, Reset, issue)
		}
		hasIssues = true
	}

	// DNS glue issues (reserved for future phases)
	if len(misconfigs.DNSGlue) > 0 {
		if hasIssues {
			fmt.Fprintf(w, "\n")
		}
		fmt.Fprintf(w, "  %sDNS Issues:%s\n", Bold, Reset)
		for _, issue := range misconfigs.DNSGlue {
			fmt.Fprintf(w, "    %s⚠%s %s\n", Red, Reset, issue)
		}
		hasIssues = true
	}

	if !hasIssues {
		fmt.Fprintf(w, "  %s✓ No misconfigurations detected%s\n", Green, Reset)
	}

	fmt.Fprintf(w, "\n")
	return nil
}