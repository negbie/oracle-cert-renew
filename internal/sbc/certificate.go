package sbc

import (
	"crypto/x509"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
)

// CertificateRecord represents a certificate record configuration
type CertificateRecord struct {
	XMLName     xml.Name          `xml:"configElement"`
	ElementType string            `xml:"elementType"`
	Attributes  []RecordAttribute `xml:"attribute"`
}

// RecordAttribute represents a configuration attribute
type RecordAttribute struct {
	Name  string `xml:"name"`
	Value string `xml:"value"`
}

// CSRResponse represents the response when generating a CSR
type CSRResponse struct {
	XMLName xml.Name `xml:"response"`
	Data    struct {
		CertificateRequest struct {
			RecordName string `xml:"recordName"`
			CSR        string `xml:"certificateSignedRequest"`
		} `xml:"CertificateRequest"`
	} `xml:"data"`
}

// ImportCertificate represents the certificate import request
type ImportCertificateRequest struct {
	XMLName            xml.Name `xml:"ImportCertificate"`
	RecordName         string   `xml:"recordName"`
	Format             string   `xml:"format"`
	CertificateRequest string   `xml:"certificateRequest"`
	Overwrite          string   `xml:"overwrite,omitempty"`
}

// ConfigResponse represents a configuration operation response
type ConfigResponse struct {
	XMLName  xml.Name `xml:"response"`
	Messages []string `xml:"messages>message"`
	Status   string   `xml:"status"`
}

// CheckConnection verifies the connection and authentication with the SBC
func (c *Client) CheckConnection() error {
	// Fetch system status to verify connectivity and show status output
	resp, err := c.doRequest("GET", "/system/status", nil)
	if err != nil {
		return fmt.Errorf("connection test failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading system status response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("connection test failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Log and also print to stdout (stdout printing lets user see it immediately in check mode)
	log.Printf("System status response:\n%s", string(body))

	return nil
}

// CreateCertificateRecord creates or updates a certificate record on the SBC
func (c *Client) CreateCertificateRecord(force bool) error {
	log.Printf("Creating/updating certificate record: %s", c.config.Certificate.Name)

	// Acquire configuration lock
	if err := c.acquireLock(); err != nil {
		return fmt.Errorf("acquiring lock: %w", err)
	}
	// Ensure lock is released even on panic
	defer func() {
		if err := c.releaseLock(); err != nil {
			log.Printf("Warning: error releasing lock: %v", err)
		}
	}()

	// Sanitize fields that don't allow spaces - replace with hyphens
	sanitizeField := func(s string) string {
		return strings.ReplaceAll(s, " ", "-")
	}

	// Build certificate record XML
	// Valid fields for Oracle SBC certificate-record: name, country, state, locality, organization, common-name, key-size, key-algor, alternate-name
	record := CertificateRecord{
		ElementType: "certificate-record",
		Attributes: []RecordAttribute{
			{Name: "name", Value: c.config.Certificate.Name},
			{Name: "country", Value: c.config.Certificate.Country},
			{Name: "state", Value: sanitizeField(c.config.Certificate.State)},
			{Name: "organization", Value: sanitizeField(c.config.Certificate.Organization)},
			{Name: "common-name", Value: c.config.Certificate.CommonName},
			{Name: "key-size", Value: fmt.Sprintf("%d", c.config.Certificate.KeySize)},
			{Name: "key-algor", Value: c.config.Certificate.KeyAlgorithm},
		},
	}

	// Add alternate name if provided
	if c.config.Certificate.AlternateName != "" {
		record.Attributes = append(record.Attributes, RecordAttribute{
			Name:  "alternate-name",
			Value: sanitizeField(c.config.Certificate.AlternateName),
		})
	}
	if c.config.Certificate.Locality != "" {
		record.Attributes = append(record.Attributes, RecordAttribute{
			Name:  "locality",
			Value: sanitizeField(c.config.Certificate.Locality),
		})
	}

	xmlData, err := xml.MarshalIndent(record, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling record: %w", err)
	}

	// Add XML header
	xmlWithHeader := append([]byte(xml.Header), xmlData...)
	xmlData = xmlWithHeader

	// Log the XML being sent
	log.Printf("Sending XML for certificate record:\n%s", string(xmlData))

	// Check if record exists first
	recordExists, err := c.certificateRecordExists(c.config.Certificate.Name)
	if err != nil {
		return fmt.Errorf("checking existing record: %w", err)
	}

	var resp *http.Response
	if recordExists {
		if force {
			log.Printf("Certificate record %s exists; overwriting due to -force", c.config.Certificate.Name)
			resp, err = c.doRequest("PUT", "/configuration/configElements", xmlData)
		} else {
			log.Printf("Certificate record %s already exists; not modifying (use -force to overwrite)", c.config.Certificate.Name)
		}
	} else {
		log.Printf("Creating new certificate record: %s", c.config.Certificate.Name)
		resp, err = c.doRequest("POST", "/configuration/configElements", xmlData)
	}

	if resp != nil {
		if err != nil {
			action := "creating"
			if recordExists && force {
				action = "updating"
			}
			return fmt.Errorf("%s record: %w", action, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated &&
			resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusNoContent {
			body, _ := io.ReadAll(resp.Body)
			action := "create/update"
			return fmt.Errorf("certificate record %s failed with status %d: %s", action, resp.StatusCode, body)
		}
	}

	// (Status check removed for existing records since no update request is made)

	// Save configuration
	if err := c.saveAndActivateConfig(); err != nil {
		return fmt.Errorf("saving config: %w", err)
	}

	log.Println("Certificate record created/updated successfully")
	return nil
}

// GenerateCSR generates a CSR for the certificate record
func (c *Client) GenerateCSR() (string, error) {
	log.Printf("Generating CSR for record: %s", c.config.Certificate.Name)

	// Check if the certificate record exists
	exists, err := c.certificateRecordExists(c.config.Certificate.Name)
	if err != nil {
		return "", fmt.Errorf("checking certificate record: %w", err)
	}
	if !exists {
		return "", fmt.Errorf("certificate record '%s' does not exist. Create it first with -mode generate", c.config.Certificate.Name)
	}

	path := fmt.Sprintf("/configuration/certificates/generateRequest?recordName=%s", c.config.Certificate.Name)
	resp, err := c.doRequest("PUT", path, nil)
	if err != nil {
		return "", fmt.Errorf("generating CSR request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading CSR response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed with status %d: %s", resp.StatusCode, body)
	}

	var csrResp CSRResponse
	if err := xml.Unmarshal(body, &csrResp); err != nil {
		return "", fmt.Errorf("decoding CSR response: %w", err)
	}

	csr := strings.TrimSpace(csrResp.Data.CertificateRequest.CSR)
	if csr == "" {
		return "", fmt.Errorf("empty CSR received")
	}

	log.Println("CSR generated successfully")
	return csr, nil
}

// CreateCertificateRecordAndGenerateCSR performs the Oracle-documented atomic workflow:
// 1) Acquire configuration lock
// 2) POST (or PUT if force) certificate-record configElement
// 3) Save, verify, activate configuration
// 4) Generate CSR for the new certificate-record (still under the same lock)
// 5) Release configuration lock (via defer)
func (c *Client) CreateCertificateRecordAndGenerateCSR(force bool) (string, error) {
	log.Printf("Creating certificate record and generating CSR atomically: %s", c.config.Certificate.Name)

	// Step 1: Acquire lock
	if err := c.acquireLock(); err != nil {
		return "", fmt.Errorf("acquiring lock: %w", err)
	}
	defer func() {
		if err := c.releaseLock(); err != nil {
			log.Printf("Warning: error releasing lock: %v", err)
		}
	}()

	// Helper to sanitize (replace spaces)
	sanitizeField := func(s string) string {
		return strings.ReplaceAll(s, " ", "-")
	}

	// Step 2: Build certificate-record configElement XML
	record := CertificateRecord{
		ElementType: "certificate-record",
		Attributes: []RecordAttribute{
			{Name: "name", Value: c.config.Certificate.Name},
			{Name: "country", Value: c.config.Certificate.Country},
			{Name: "state", Value: sanitizeField(c.config.Certificate.State)},
			{Name: "organization", Value: sanitizeField(c.config.Certificate.Organization)},
			{Name: "common-name", Value: c.config.Certificate.CommonName},
			{Name: "key-size", Value: fmt.Sprintf("%d", c.config.Certificate.KeySize)},
			{Name: "key-algor", Value: c.config.Certificate.KeyAlgorithm},
		},
	}
	if c.config.Certificate.AlternateName != "" {
		record.Attributes = append(record.Attributes, RecordAttribute{
			Name:  "alternate-name",
			Value: sanitizeField(c.config.Certificate.AlternateName),
		})
	}
	if c.config.Certificate.Locality != "" {
		record.Attributes = append(record.Attributes, RecordAttribute{
			Name:  "locality",
			Value: sanitizeField(c.config.Certificate.Locality),
		})
	}

	xmlData, err := xml.MarshalIndent(record, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshaling record: %w", err)
	}
	xmlData = append([]byte(xml.Header), xmlData...)

	log.Printf("Certificate-record XML (atomic op):\n%s", string(xmlData))

	exists, err := c.certificateRecordExists(c.config.Certificate.Name)
	if err != nil {
		return "", fmt.Errorf("checking existing record: %w", err)
	}

	var resp *http.Response
	if exists {
		if force {
			log.Printf("Certificate record %s exists; overwriting due to -force", c.config.Certificate.Name)
			resp, err = c.doRequest("PUT", "/configuration/configElements", xmlData)
			if err != nil {
				return "", fmt.Errorf("updating record: %w", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated &&
				resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusNoContent {
				body, _ := io.ReadAll(resp.Body)
				return "", fmt.Errorf("certificate-record update failed with status %d: %s", resp.StatusCode, body)
			}
		} else {
			log.Printf("Certificate record %s already exists; not modifying (use -force to overwrite)", c.config.Certificate.Name)
		}
	} else {
		resp, err = c.doRequest("POST", "/configuration/configElements", xmlData)
		if err != nil {
			return "", fmt.Errorf("creating record: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated &&
			resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusNoContent {
			body, _ := io.ReadAll(resp.Body)
			return "", fmt.Errorf("certificate-record create failed with status %d: %s", resp.StatusCode, body)
		}
	}

	// Step 3: Generate CSR under same lock
	csrEndpoint := fmt.Sprintf("/configuration/certificates/generateRequest?recordName=%s", c.config.Certificate.Name)
	csrResp, err := c.doRequest("PUT", csrEndpoint, nil)
	if err != nil {
		return "", fmt.Errorf("generating CSR request: %w", err)
	}
	defer csrResp.Body.Close()

	csrBody, err := io.ReadAll(csrResp.Body)
	if err != nil {
		return "", fmt.Errorf("reading CSR response: %w", err)
	}
	if csrResp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("CSR request failed with status %d: %s", csrResp.StatusCode, csrBody)
	}

	var parsed CSRResponse
	if err := xml.Unmarshal(csrBody, &parsed); err != nil {
		return "", fmt.Errorf("decoding CSR response: %w", err)
	}
	csr := strings.TrimSpace(parsed.Data.CertificateRequest.CSR)
	if csr == "" {
		return "", fmt.Errorf("empty CSR received")
	}

	if exists && !force {
		return "", fmt.Errorf("certificate already exists")
	}

	// Step 4: Save / verify / activate
	if err := c.saveAndActivateConfig(); err != nil {
		return "", fmt.Errorf("saving/activating config: %w", err)
	}

	log.Println("Certificate record created/updated, configuration activated, and CSR generated (single lock session).")
	return csr, nil
}

// ImportCertificate imports a signed certificate by first attempting WITHOUT an <overwrite>
// element (as per Oracle docs a simple import/update can succeed without it). If that fails,
// it retries once WITH <overwrite>true</overwrite>. The certificate body is passed through
// exactly as provided (no trimming, re-wrapping, or encoding changes).
func (c *Client) ImportCertificate(certificateData string, force bool) error {
	if !strings.Contains(certificateData, "-----BEGIN CERTIFICATE-----") ||
		!strings.Contains(certificateData, "-----END CERTIFICATE-----") {
		return fmt.Errorf("invalid certificate: missing BEGIN/END CERTIFICATE markers")
	}

	// Ensure record exists
	exists, err := c.certificateRecordExists(c.config.Certificate.Name)
	if err != nil {
		return fmt.Errorf("checking certificate record: %w", err)
	}
	if !exists {
		return fmt.Errorf("certificate record '%s' does not exist. Create it first with -mode generate",
			c.config.Certificate.Name)
	}

	// Validate intermediate (CA) certificate Common Names against trusted list if configured.
	// This enforces that any CA / intermediate certificates contained in the provided bundle
	// have a Subject CN explicitly listed in tls_profile.trusted-ca-certificates.
	if c.config.TLSProfile.Enabled && len(c.config.TLSProfile.TrustedCACertificates) > 0 { // TrustedCACertificates parsed via CSVStringList
		log.Printf("[import] Validating intermediate CA CNs against allowlist: %v",
			c.config.TLSProfile.TrustedCACertificates)
		allowed := make(map[string]struct{}, len(c.config.TLSProfile.TrustedCACertificates))
		for _, v := range c.config.TLSProfile.TrustedCACertificates {
			allowed[v] = struct{}{}
		}

		var foundIntermediates []string
		rest := []byte(certificateData)
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				continue
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				log.Printf("[import] Skipping unparsable certificate in bundle: %v", err)
				continue
			}
			// Only evaluate CA/intermediate certificates; the leaf (end-entity) is not required to match.
			if cert.IsCA {
				cn := cert.Subject.CommonName
				foundIntermediates = append(foundIntermediates, cn)
				if _, ok := allowed[cn]; !ok {
					return fmt.Errorf("intermediate certificate CN %q not in trusted-ca-certificates allowlist", cn)
				}
			}
		}

		if len(foundIntermediates) == 0 {
			log.Printf("[import] No intermediate/CA certificates detected in provided bundle (nothing to validate)")
		} else {
			log.Printf("[import] Intermediate CNs validated successfully: %v", foundIntermediates)
		}
	}

	// Acquire lock
	if err := c.acquireLock(); err != nil {
		return fmt.Errorf("acquiring lock: %w", err)
	}
	defer func() {
		if err := c.releaseLock(); err != nil {
			log.Printf("Warning: error releasing lock: %v", err)
		}
	}()

	// Minimal suspicious marker check
	for _, m := range []string{"<edits>", "<old_text", "<new_text"} {
		if strings.Contains(certificateData, m) {
			return fmt.Errorf("abort: suspicious non-certificate marker %q in certificate data", m)
		}
	}

	// Debug
	// Minimal verbose note (removed detailed hex/hash debug)
	log.Printf("[import] Preparing certificate import (length=%d bytes)", len(certificateData))

	escape := func(s string) string {
		var b strings.Builder
		for _, r := range s {
			switch r {
			case '&':
				b.WriteString("&amp;")
			case '<':
				b.WriteString("&lt;")
			case '>':
				b.WriteString("&gt;")
			case '"':
				b.WriteString("&quot;")
			case '\'':
				b.WriteString("&apos;")
			default:
				b.WriteRune(r)
			}
		}
		return b.String()
	}

	buildXML := func(includeOverwrite bool) []byte {
		var sb strings.Builder
		sb.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
		sb.WriteString("<ImportCertificate>\n")
		sb.WriteString("  <recordName>")
		sb.WriteString(escape(c.config.Certificate.Name))
		sb.WriteString("</recordName>\n")
		sb.WriteString("  <format>x509</format>\n")
		sb.WriteString("  <certificateRequest>")
		sb.WriteString(certificateData) // EXACT
		sb.WriteString("</certificateRequest>\n")
		if includeOverwrite {
			sb.WriteString("  <overwrite>true</overwrite>\n")
		}
		sb.WriteString("</ImportCertificate>")
		return []byte(sb.String())
	}

	type attempt struct {
		name             string
		payload          []byte
		includeOverwrite bool
	}
	attempts := []attempt{
		{name: "no-overwrite", payload: buildXML(false), includeOverwrite: false},
	}
	if force {
		attempts = append(attempts, attempt{name: "with-overwrite", payload: buildXML(true), includeOverwrite: true})
	}

	var lastStatus int
	var lastRespBody string
	for i, at := range attempts {
		log.Printf("[import] Attempt %d/%d (%s) XML length=%d",
			i+1, len(attempts), at.name, len(at.payload))

		resp, err := c.doRequest("PUT", "/configuration/certificates/import", at.payload)
		if err != nil {
			return fmt.Errorf("import %s (PUT): %w", at.name, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		lastStatus = resp.StatusCode
		lastRespBody = string(body)

		// Special quorum for 400 "request body not found" -> POST retry
		if resp.StatusCode == http.StatusBadRequest &&
			strings.Contains(strings.ToLower(lastRespBody), "request body not found") {
			log.Printf("[import] %s: PUT -> 400 'request body not found', retrying with POST", at.name)
			resp, err = c.doRequest("POST", "/configuration/certificates/import", at.payload)
			if err != nil {
				return fmt.Errorf("import %s (POST retry): %w", at.name, err)
			}
			body, _ = io.ReadAll(resp.Body)
			resp.Body.Close()
			lastStatus = resp.StatusCode
			lastRespBody = string(body)
		}

		if lastStatus == http.StatusOK || lastStatus == http.StatusAccepted || lastStatus == http.StatusNoContent {
			log.Printf("[import] %s succeeded (status %d)", at.name, lastStatus)
			// Save & activate
			if err := c.saveAndActivateConfig(); err != nil {
				return fmt.Errorf("saving config after import: %w", err)
			}
			if err := c.UpdateTLSProfileAfterImport(); err != nil {
				return fmt.Errorf("updating TLS profile: %w", err)
			}
			log.Printf("Certificate imported successfully using attempt '%s'", at.name)
			return nil
		}

		log.Printf("[import] %s failed status=%d body:\n%s", at.name, lastStatus, lastRespBody)

		// Only fall through to second attempt if first failed
	}

	return fmt.Errorf("certificate import failed after %d attempts (last status %d): %s",
		len(attempts), lastStatus, lastRespBody)
}

// (Legacy RenewCertificate method removed; explicit modes handle workflow)

// certificateRecordExists checks if a certificate record exists on the SBC
func (c *Client) certificateRecordExists(recordName string) (bool, error) {
	checkPath := fmt.Sprintf("/configuration/configElements?elementType=certificate-record&name=%s", recordName)
	resp, err := c.doRequest("GET", checkPath, nil)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		// Check if the response actually contains the record
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return false, err
		}
		// If response contains the record name, it exists
		return strings.Contains(string(body), recordName), nil
	}

	return false, nil
}

// acquireLock acquires the configuration lock
func (c *Client) acquireLock() error {
	log.Println("Acquiring configuration lock...")

	resp, err := c.doRequest("POST", "/configuration/lock", nil)
	if err != nil {
		return fmt.Errorf("requesting lock: %w", err)
	}
	defer resp.Body.Close()

	// Handle different response codes according to Oracle SBC REST API
	switch resp.StatusCode {
	case http.StatusNoContent: // 204 - Successfully acquired lock

	case http.StatusLocked: // 423 - Lock held by another user/session
		body, _ := io.ReadAll(resp.Body)
		// Check if we might already hold the lock
		if strings.Contains(string(body), "already locked") && strings.Contains(string(body), "current session") {
			c.hasLock = true
			log.Println("Configuration lock already held by this session")
			return nil
		}
		return fmt.Errorf("configuration is locked by another user or session. " +
			"Configuration locks are tied to authentication tokens and cannot be released by other sessions. " +
			"Please wait for the lock to expire (typically 5-10 minutes of inactivity) and try again")

	case http.StatusOK, http.StatusAccepted: // Alternative success codes
		c.hasLock = true
		log.Println("Configuration lock acquired")
		return nil

	default:
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to acquire lock with status %d: %s", resp.StatusCode, body)
	}

	c.hasLock = true
	log.Println("Configuration lock acquired")
	return nil
}

// releaseLock releases the configuration lock
func (c *Client) releaseLock() error {
	// Only try to release if we have a lock
	if !c.hasLock {
		return nil
	}

	// Always mark as not having lock after this function
	defer func() {
		c.hasLock = false
	}()

	log.Println("Releasing configuration lock...")

	resp, err := c.doRequest("POST", "/configuration/unlock", nil)
	if err != nil {
		// Log but don't return error for unlock failures
		log.Printf("Warning: failed to release lock: %v", err)
		return nil
	}
	defer resp.Body.Close()

	// Handle different response codes according to Oracle SBC REST API
	switch resp.StatusCode {
	case http.StatusNoContent: // 204 - Successfully released lock
		c.hasLock = false
		log.Println("Configuration lock released")
		return nil

	case http.StatusLocked: // 423 - User does not have the lock
		body, _ := io.ReadAll(resp.Body)
		log.Printf("Lock was not held by this session: %s", body)
		c.hasLock = false
		return nil

	case http.StatusOK, http.StatusAccepted: // Alternative success codes
		c.hasLock = false
		log.Println("Configuration lock released")
		return nil

	default:
		body, _ := io.ReadAll(resp.Body)
		log.Printf("Warning: unexpected unlock response with status %d: %s", resp.StatusCode, body)
		c.hasLock = false
		return nil
	}
}

// TryUnlock attempts to release the configuration lock
// Note: You can only release a lock held by your current token/session
func (c *Client) TryUnlock() error {
	log.Println("Attempting to release configuration lock (if held by current session)...")

	// Try to unlock - this only works if we hold the lock with our current token
	resp, err := c.doRequest("POST", "/configuration/unlock", nil)
	if err != nil {
		return fmt.Errorf("unlock request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	switch resp.StatusCode {
	case http.StatusNoContent:
		log.Println("Lock successfully released")
		c.hasLock = false
		return nil
	case http.StatusLocked:
		return fmt.Errorf("cannot release lock - it is held by another token/session. "+
			"Configuration locks are tied to authentication tokens. "+
			"You must wait for the lock to expire (typically 5-10 minutes of inactivity). "+
			"Details: %s", string(body))
	default:
		return fmt.Errorf("unexpected response (status %d): %s", resp.StatusCode, string(body))
	}
}

// saveAndActivateConfig saves, verifies, and activates the configuration
func (c *Client) saveAndActivateConfig() error {
	// Save configuration
	log.Println("Saving configuration...")

	resp, err := c.doRequest("PUT", "/configuration/management?action=save", nil)
	if err != nil {
		return fmt.Errorf("saving config: %w", err)
	}

	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("save failed with status %d: %s", resp.StatusCode, body)
	}

	log.Println("Configuration saved")

	// Verify configuration
	log.Println("Verifying configuration...")

	resp, err = c.doRequest("PUT", "/configuration/management?action=verify", nil)
	if err != nil {
		return fmt.Errorf("verifying config: %w", err)
	}

	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusNoContent {
		// Log warning but don't fail if verification has warnings
		log.Printf("Warning: Configuration verification returned status %d: %s", resp.StatusCode, body)
	}

	log.Println("Configuration verified")

	// Activate configuration
	log.Println("Activating configuration...")

	resp, err = c.doRequest("POST", "/configuration/management?action=activate", nil)
	if err != nil {
		return fmt.Errorf("activating config: %w", err)
	}

	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("activate failed with status %d: %s", resp.StatusCode, body)
	}

	log.Println("Configuration activated")

	return nil
}
