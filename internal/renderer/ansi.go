package renderer

import (
	"fmt"
	"io"
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

func (a *ANSIRenderer) Render(w io.Writer, report *models.Report) error {
	if report == nil {
		return fmt.Errorf("report cannot be nil")
	}

	// Header
	fmt.Fprintf(w, "═══ checks.sh ═══\n")
	fmt.Fprintf(w, "Target: %s\n", report.Target)
	fmt.Fprintf(w, "Scanned: %s\n\n", report.Timestamp.UTC().Format(time.RFC3339))

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
	fmt.Fprintf(w, "[ IDENTITY ]\n")

	if identity.IP != "" {
		fmt.Fprintf(w, "  IP Address: %s\n", identity.IP)
	}

	if len(identity.Nameservers) > 0 {
		fmt.Fprintf(w, "  Nameservers:\n")
		for _, ns := range identity.Nameservers {
			fmt.Fprintf(w, "    • %s\n", ns)
		}
	}

	// Only show WHOIS fields if they have values (Phase 2+ features)
	if identity.Registrar != "" {
		fmt.Fprintf(w, "  Registrar: %s\n", identity.Registrar)
	}

	if identity.Owner != "" {
		fmt.Fprintf(w, "  Owner: %s\n", identity.Owner)
	}

	if identity.ExpiresDays > 0 {
		fmt.Fprintf(w, "  Expires: %d days\n", identity.ExpiresDays)
	}

	fmt.Fprintf(w, "\n")
	return nil
}

func (a *ANSIRenderer) renderCertificates(w io.Writer, certs *models.Certificates) error {
	fmt.Fprintf(w, "[ CERTIFICATES ]\n")

	// Current certificate
	if certs.Current.CommonName != "" {
		fmt.Fprintf(w, "  Current Certificate:\n")
		fmt.Fprintf(w, "    Common Name: %s", certs.Current.CommonName)

		if certs.Current.IsWildcard {
			fmt.Fprintf(w, " (wildcard)")
		}
		fmt.Fprintf(w, "\n")

		if certs.Current.Issuer != "" {
			fmt.Fprintf(w, "    Issuer: %s\n", certs.Current.Issuer)
		}

		fmt.Fprintf(w, "    Status: %s\n", certs.Current.Status)

		if !certs.Current.NotAfter.IsZero() {
			expiry := certs.Current.NotAfter.Format("2006-01-02")
			daysUntilExpiry := int(time.Until(certs.Current.NotAfter).Hours() / 24)

			fmt.Fprintf(w, "    Expires: %s (%d days)\n", expiry, daysUntilExpiry)
		}
	} else {
		fmt.Fprintf(w, "  No certificate information available\n")
	}

	fmt.Fprintf(w, "\n")
	return nil
}

func (a *ANSIRenderer) renderMisconfigurations(w io.Writer, misconfigs *models.Misconfigurations) error {
	fmt.Fprintf(w, "[ MISCONFIGURATIONS ]\n")

	hasIssues := false

	// Email security
	if misconfigs.EmailSec.SPF != "" || misconfigs.EmailSec.DMARC != "" {
		fmt.Fprintf(w, "  Email Security:\n")

		if misconfigs.EmailSec.SPF != "" {
			fmt.Fprintf(w, "    SPF: %s\n", misconfigs.EmailSec.SPF)
		}

		if misconfigs.EmailSec.DMARC != "" {
			fmt.Fprintf(w, "    DMARC Policy: %s\n", misconfigs.EmailSec.DMARC)
		}

		if misconfigs.EmailSec.IsWeak {
			fmt.Fprintf(w, "    ⚠ Weak email security configuration\n")
		}

		hasIssues = true
	}

	// Header issues
	if len(misconfigs.Headers) > 0 {
		if hasIssues {
			fmt.Fprintf(w, "\n")
		}
		fmt.Fprintf(w, "  Security Headers:\n")
		for _, issue := range misconfigs.Headers {
			fmt.Fprintf(w, "    ⚠ %s\n", issue)
		}
		hasIssues = true
	}

	// DNS glue issues (reserved for future phases)
	if len(misconfigs.DNSGlue) > 0 {
		if hasIssues {
			fmt.Fprintf(w, "\n")
		}
		fmt.Fprintf(w, "  DNS Issues:\n")
		for _, issue := range misconfigs.DNSGlue {
			fmt.Fprintf(w, "    ⚠ %s\n", issue)
		}
		hasIssues = true
	}

	if !hasIssues {
		fmt.Fprintf(w, "  ✓ No misconfigurations detected\n")
	}

	fmt.Fprintf(w, "\n")
	return nil
}
