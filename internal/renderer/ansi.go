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

	// Findings section
	if err := a.renderFindings(w, &report.Findings); err != nil {
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

	// WHOIS information
	if identity.Registrar != "" {
		fmt.Fprintf(w, "  Registrar: %s\n", identity.Registrar)
	}

	if identity.Owner != "" {
		fmt.Fprintf(w, "  Owner: %s\n", identity.Owner)
	}

	if identity.ExpiresDays > 0 {
		fmt.Fprintf(w, "  Domain Expires: %d days\n", identity.ExpiresDays)
	} else if identity.ExpiresDays < 0 && identity.Registrar != "" {
		// WHOIS was attempted but expiry date couldn't be parsed
		fmt.Fprintf(w, "  Domain Expires: Unknown\n")
	}

	// DNSSEC
	if identity.DNSSECEnabled {
		if identity.DNSSECValid {
			fmt.Fprintf(w, "  DNSSEC: ✓ Enabled and Valid\n")
		} else {
			fmt.Fprintf(w, "  DNSSEC: ⚠ Enabled but Invalid\n")
			if identity.DNSSECError != "" {
				fmt.Fprintf(w, "    Error: %s\n", identity.DNSSECError)
			}
		}
	} else {
		fmt.Fprintf(w, "  DNSSEC: ✗ Not Enabled\n")
	}

	// CAA Records
	if len(identity.CAARecords) > 0 {
		fmt.Fprintf(w, "  CAA Records:\n")
		for _, caa := range identity.CAARecords {
			fmt.Fprintf(w, "    • %s\n", caa)
		}
	} else if identity.CAAMissing {
		fmt.Fprintf(w, "  CAA Records: ⚠ Missing\n")
	}

	fmt.Fprintf(w, "\n")
	return nil
}

func (a *ANSIRenderer) renderCertificates(w io.Writer, certs *models.Certificates) error {
	fmt.Fprintf(w, "[ CERTIFICATES ]\n")

	// Current certificate
	if certs.CommonName != "" {
		fmt.Fprintf(w, "  Current Certificate:\n")
		fmt.Fprintf(w, "    Common Name: %s", certs.CommonName)

		if certs.IsWildcard {
			fmt.Fprintf(w, " (wildcard)")
		}
		fmt.Fprintf(w, "\n")

		if certs.Issuer != "" {
			fmt.Fprintf(w, "    Issuer: %s\n", certs.Issuer)
		}

		fmt.Fprintf(w, "    Status: %s\n", certs.Status)

		if !certs.NotAfter.IsZero() {
			expiry := certs.NotAfter.Format("2006-01-02")
			daysUntilExpiry := int(time.Until(certs.NotAfter).Hours() / 24)

			fmt.Fprintf(w, "    Expires: %s (%d days)\n", expiry, daysUntilExpiry)
		}
	} else {
		fmt.Fprintf(w, "  No certificate information available\n")
	}

	// TLS Analysis
	if len(certs.TLSVersions) > 0 {
		fmt.Fprintf(w, "\n  TLS Configuration:\n")

		// TLS Versions
		fmt.Fprintf(w, "    Supported TLS Versions: ")
		for i, version := range certs.TLSVersions {
			if i > 0 {
				fmt.Fprintf(w, ", ")
			}
			fmt.Fprintf(w, "%s", version)
		}
		fmt.Fprintf(w, "\n")

		// Weak TLS Versions
		if len(certs.WeakTLSVersions) > 0 {
			fmt.Fprintf(w, "    ⚠ Weak TLS Versions: ")
			for i, version := range certs.WeakTLSVersions {
				if i > 0 {
					fmt.Fprintf(w, ", ")
				}
				fmt.Fprintf(w, "%s", version)
			}
			fmt.Fprintf(w, "\n")
		}

		// Cipher Suites (show count to avoid clutter)
		if len(certs.CipherSuites) > 0 {
			fmt.Fprintf(w, "    Cipher Suites: %d detected\n", len(certs.CipherSuites))
		}

		// Weak Cipher Suites
		if len(certs.WeakCipherSuites) > 0 {
			fmt.Fprintf(w, "    ⚠ Weak Cipher Suites:\n")
			for _, cipher := range certs.WeakCipherSuites {
				fmt.Fprintf(w, "      • %s\n", cipher)
			}
		}
	}

	fmt.Fprintf(w, "\n")
	return nil
}

func (a *ANSIRenderer) renderFindings(w io.Writer, findings *models.Findings) error {
	fmt.Fprintf(w, "[ FINDINGS ]\n")

	hasIssues := false

	// HTTPS Redirect - only show if data is present (not default empty struct)
	hasRedirectData := findings.HTTPSRedirect.Enabled ||
		findings.HTTPSRedirect.StatusCode != 0 ||
		findings.HTTPSRedirect.Error != "" ||
		findings.HTTPSRedirect.RedirectLoop

	if hasRedirectData {
		if findings.HTTPSRedirect.Enabled {
			fmt.Fprintf(w, "  HTTPS Redirect: ✓ Enabled\n")
			if findings.HTTPSRedirect.FinalURL != "" {
				fmt.Fprintf(w, "    Final URL: %s\n", findings.HTTPSRedirect.FinalURL)
			}
		} else {
			fmt.Fprintf(w, "  HTTPS Redirect: ⚠ Not Configured\n")
			if findings.HTTPSRedirect.Error != "" {
				fmt.Fprintf(w, "    Error: %s\n", findings.HTTPSRedirect.Error)
			}
			hasIssues = true
		}

		if findings.HTTPSRedirect.RedirectLoop {
			fmt.Fprintf(w, "    ⚠ Redirect loop detected\n")
			hasIssues = true
		}
	}

	// Email security
	if findings.EmailSec.SPF != "" || findings.EmailSec.DMARC != "" {
		fmt.Fprintf(w, "\n  Email Security:\n")

		if findings.EmailSec.SPF != "" {
			fmt.Fprintf(w, "    SPF: %s\n", findings.EmailSec.SPF)
		}

		if findings.EmailSec.DMARC != "" {
			fmt.Fprintf(w, "    DMARC Policy: %s\n", findings.EmailSec.DMARC)
		}

		if findings.EmailSec.IsWeak {
			fmt.Fprintf(w, "    ⚠ Weak email security configuration\n")
			hasIssues = true
		}
	}

	// Header issues
	if len(findings.Headers) > 0 {
		fmt.Fprintf(w, "\n  Security Headers:\n")
		for _, issue := range findings.Headers {
			fmt.Fprintf(w, "    ⚠ %s\n", issue)
		}
		hasIssues = true
	}

	// DNS glue issues (reserved for future phases)
	if len(findings.DNSGlue) > 0 {
		fmt.Fprintf(w, "\n  DNS Issues:\n")
		for _, issue := range findings.DNSGlue {
			fmt.Fprintf(w, "    ⚠ %s\n", issue)
		}
		hasIssues = true
	}

	if !hasIssues {
		fmt.Fprintf(w, "  ✓ No findings detected\n")
	}

	fmt.Fprintf(w, "\n")
	return nil
}
