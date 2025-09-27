package sbc

import (
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
)

// TLSProfileAttribute represents an attribute in the TLS profile configuration
type TLSProfileAttribute struct {
	Name  string `xml:"name"`
	Value string `xml:"value"`
}

// TLSProfileElement represents a TLS profile configuration element
type TLSProfileElement struct {
	XMLName     xml.Name              `xml:"configElement"`
	ElementType string                `xml:"elementType"`
	Attributes  []TLSProfileAttribute `xml:"attribute"`
}

// GetTLSProfile retrieves the current TLS profile configuration
func (c *Client) GetTLSProfile(profileName string) (*TLSProfileElement, error) {
	if profileName == "" {
		profileName = "defaultTlsProfile"
	}

	resp, err := c.doRequest("GET", fmt.Sprintf("/configuration/configElements?elementType=tls-profile&name=%s", profileName), nil)
	if err != nil {
		return nil, fmt.Errorf("getting TLS profile: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get TLS profile with status %d: %s", resp.StatusCode, body)
	}

	// Parse the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	var response struct {
		ConfigElements []TLSProfileElement `xml:"configElement"`
	}

	if err := xml.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("parsing TLS profile response: %w", err)
	}

	if len(response.ConfigElements) == 0 {
		return nil, fmt.Errorf("TLS profile '%s' not found", profileName)
	}

	return &response.ConfigElements[0], nil
}

// UpdateTLSProfile updates the TLS profile to use the new certificate
func (c *Client) UpdateTLSProfile(profileName, certificateName string) error {
	if profileName == "" {
		profileName = "defaultTlsProfile"
	}

	log.Printf("Updating TLS profile '%s' to use certificate '%s'", profileName, certificateName)

	// Build TLS profile update
	profile := &TLSProfileElement{
		ElementType: "tls-profile",
		Attributes: []TLSProfileAttribute{
			{Name: "name", Value: profileName},
			{Name: "end-entity-certificate", Value: certificateName},
		},
	}

	// Marshal the profile with proper formatting
	xmlData, err := xml.MarshalIndent(profile, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling TLS profile: %w", err)
	}

	// Add XML header
	xmlWithHeader := append([]byte(xml.Header), xmlData...)
	xmlData = xmlWithHeader

	// Unconditional logging (verbose removed)
	log.Printf("Sending XML for TLS profile update:\n%s", string(xmlData))

	// Update the TLS profile using the generic configElements endpoint (Oracle expects PUT to /configuration/configElements)
	updatePath := "/configuration/configElements"
	resp, err := c.doRequest("PUT", updatePath, xmlData)
	if err != nil {
		return fmt.Errorf("updating TLS profile: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to update TLS profile (endpoint %s) with status %d: %s", updatePath, resp.StatusCode, body)
	}

	log.Printf("TLS profile '%s' updated successfully", profileName)
	return nil
}

// DeleteCertificateRecord deletes an old certificate record
func (c *Client) DeleteCertificateRecord(recordName string) error {
	if recordName == "" {
		return fmt.Errorf("certificate record name is required")
	}

	log.Printf("Deleting old certificate record '%s'", recordName)

	resp, err := c.doRequest("DELETE", fmt.Sprintf("/configuration/configElements?elementType=certificate-record&name=%s", recordName), nil)
	if err != nil {
		return fmt.Errorf("deleting certificate record: %w", err)
	}
	defer resp.Body.Close()

	// 404 is okay - certificate might not exist
	if resp.StatusCode == http.StatusNotFound {
		log.Printf("Certificate record '%s' not found (already deleted?)", recordName)
		return nil
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to delete certificate record with status %d: %s", resp.StatusCode, body)
	}

	log.Printf("Certificate record '%s' deleted successfully", recordName)
	return nil
}

// UpdateTLSProfileAfterImport handles the complete TLS profile update process after certificate import
func (c *Client) UpdateTLSProfileAfterImport() error {
	if !c.config.TLSProfile.Enabled {
		log.Println("TLS profile update is disabled in configuration")
		return nil
	}

	if !c.config.TLSProfile.UpdateAfterImport {
		log.Println("TLS profile auto-update after import is disabled")
		return nil
	}

	log.Println("Updating TLS profile after certificate import...")

	// Acquire configuration lock only if not already held
	acquiredHere := false
	if !c.hasLock {
		if err := c.acquireLock(); err != nil {
			return fmt.Errorf("acquiring lock for TLS profile update: %w", err)
		}
		acquiredHere = true
	}
	defer func() {
		if acquiredHere {
			if err := c.releaseLock(); err != nil {
				log.Printf("Warning: error releasing lock: %v", err)
			}
		}
	}()

	// Update TLS profile
	if err := c.UpdateTLSProfile(c.config.TLSProfile.ProfileName, c.config.Certificate.Name); err != nil {
		return fmt.Errorf("updating TLS profile: %w", err)
	}

	// Delete old certificate if configured
	if c.config.TLSProfile.DeleteOldCertificate && c.config.TLSProfile.OldCertificateName != "" {
		if err := c.DeleteCertificateRecord(c.config.TLSProfile.OldCertificateName); err != nil {
			// Log the error but don't fail the whole process
			log.Printf("Warning: Failed to delete old certificate: %v", err)
		}
	}

	// Save and activate configuration
	if err := c.saveAndActivateConfig(); err != nil {
		return fmt.Errorf("saving config after TLS profile update: %w", err)
	}

	log.Println("TLS profile updated successfully")

	return nil
}
