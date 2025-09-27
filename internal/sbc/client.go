package sbc

import (
	"bytes"
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/negbie/oracle-cert-renew/internal/config"
)

// Client represents an Oracle SBC REST API client
type Client struct {
	config     *config.Config
	httpClient *http.Client
	baseURL    string
	token      string
	hasLock    bool
}

// AuthResponse represents the authentication response
type AuthResponse struct {
	XMLName     xml.Name `xml:"response"`
	AccessToken string   `xml:"data>accessToken"`
	TokenType   string   `xml:"data>token_type"`
	ExpiresIn   int      `xml:"data>expires_in"`
}

// ErrorResponse represents an error response from the API
type ErrorResponse struct {
	XMLName xml.Name `xml:"response"`
	Error   struct {
		Message string `xml:"message"`
		Code    string `xml:"code"`
		Details string `xml:"details"`
	} `xml:"error"`
}

// NewClient creates a new SBC client
func NewClient(cfg *config.Config) (*Client, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.SBC.Insecure,
		},
		MaxIdleConns:       10,
		IdleConnTimeout:    30 * time.Second,
		DisableCompression: true,
	}

	client := &Client{
		config: cfg,
		httpClient: &http.Client{
			Transport: tr,
			Timeout:   60 * time.Second,
		},
		baseURL: fmt.Sprintf("https://%s:%d/rest/v1.2", cfg.SBC.Host, cfg.SBC.Port),
	}

	if err := client.authenticate(); err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	return client, nil
}

// authenticate obtains an access token from the SBC
func (c *Client) authenticate() error {
	authURL := fmt.Sprintf("%s/auth/token", c.baseURL)
	log.Printf("Authenticating to: %s", authURL)

	req, err := http.NewRequest("POST", authURL, nil)
	if err != nil {
		return fmt.Errorf("creating auth request: %w", err)
	}

	req.SetBasicAuth(c.config.SBC.Username, c.config.SBC.Password)
	req.Header.Set("Accept", "application/xml")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("executing auth request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading auth response: %w", err)
	}

	log.Printf("Auth response status: %d", resp.StatusCode)
	log.Printf("Auth response body: %s", string(body))

	if resp.StatusCode != http.StatusOK {
		var errResp ErrorResponse
		if err := xml.Unmarshal(body, &errResp); err == nil && errResp.Error.Message != "" {
			return fmt.Errorf("authentication failed: %s (code: %s)", errResp.Error.Message, errResp.Error.Code)
		}
		return fmt.Errorf("authentication failed with status %d: %s", resp.StatusCode, body)
	}

	var authResp AuthResponse
	if err := xml.Unmarshal(body, &authResp); err != nil {
		log.Printf("Failed to decode auth response as XML: %v", err)
		return fmt.Errorf("decoding auth response: %w", err)
	}

	log.Printf("Parsed auth response - AccessToken present: %v", authResp.AccessToken != "")

	if authResp.AccessToken == "" {
		return fmt.Errorf("empty access token received")
	}

	c.token = authResp.AccessToken
	return nil
}

// doRequest executes an authenticated HTTP request
func (c *Client) doRequest(method, path string, body []byte) (*http.Response, error) {
	url := fmt.Sprintf("%s%s", c.baseURL, path)

	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))
	req.Header.Set("Accept", "application/xml")
	if body != nil {
		req.Header.Set("Content-Type", "application/xml")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}

	// Check if token expired and retry once
	if resp.StatusCode == http.StatusUnauthorized {
		resp.Body.Close()

		// Re-authenticate
		if err := c.authenticate(); err != nil {
			return nil, fmt.Errorf("re-authentication failed: %w", err)
		}

		// Update the authorization header with new token
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))

		// Retry the request
		if body != nil {
			req.Body = io.NopCloser(bytes.NewReader(body))
		}

		resp, err = c.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("executing request after re-auth: %w", err)
		}
	}

	return resp, nil
}

// Close closes the client and releases resources
func (c *Client) Close() error {
	// Always try to release lock on close if we have one
	if c.hasLock {
		if err := c.releaseLock(); err != nil {
			log.Printf("Warning: failed to release lock on close: %v", err)
		}
	}
	return nil
}

// ForceClose now just calls Close
func (c *Client) ForceClose() error {
	return c.Close()
}
