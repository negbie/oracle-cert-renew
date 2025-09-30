package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds the application configuration
type Config struct {
	SBC struct {
		Host     string `yaml:"host"`
		Port     int    `yaml:"port"`
		Username string `yaml:"username"`
		Password string `yaml:"password"`
		Insecure bool   `yaml:"insecure"`
	} `yaml:"sbc"`

	Certificate struct {
		Name          string `yaml:"name"`
		Country       string `yaml:"country"`
		State         string `yaml:"state"`
		Locality      string `yaml:"locality"` // Optional (city). Included in certificate record if set.
		Organization  string `yaml:"organization"`
		CommonName    string `yaml:"common_name"`
		AlternateName string `yaml:"alternate_name"`
		KeySize       int    `yaml:"key_size"`
		KeyAlgorithm  string `yaml:"key_algorithm"`
		CertPath      string `yaml:"cert_path"`
		CSRPath       string `yaml:"csr_path"`
	} `yaml:"certificate"`

	TLSProfile struct {
		Enabled               bool          `yaml:"enabled"`
		ProfileName           string        `yaml:"profile_name"`
		UpdateAfterImport     bool          `yaml:"update_after_import"`
		DeleteOldCertificate  bool          `yaml:"delete_old_certificate"`
		OldCertificateName    string        `yaml:"old_certificate_name"`
		TrustedCACertificates CSVStringList `yaml:"trusted-ca-certificates"` // Comma separated list in config (e.g. "R10,R11")
	} `yaml:"tls_profile"`

	// Verbose field removed (was: Verbose bool `yaml:"verbose"`)
}

type CSVStringList []string

// UnmarshalYAML implements custom CSV -> []string parsing with trimming & de-duplication.
func (l *CSVStringList) UnmarshalYAML(value *yaml.Node) error {
	var raw string
	if err := value.Decode(&raw); err != nil {
		return err
	}
	if raw == "" {
		*l = nil
		return nil
	}
	parts := strings.Split(raw, ",")
	seen := make(map[string]struct{})
	var out []string
	for _, p := range parts {
		v := strings.TrimSpace(p)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	*l = out
	return nil
}

// Load reads and parses the configuration file
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	return &cfg, nil
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.SBC.Host == "" {
		return fmt.Errorf("SBC host is required")
	}
	if c.SBC.Port == 0 {
		c.SBC.Port = 443
	}
	if c.SBC.Username == "" {
		return fmt.Errorf("SBC username is required")
	}
	if c.SBC.Password == "" {
		return fmt.Errorf("SBC password is required")
	}
	if c.Certificate.Name == "" {
		// Default: short month (lowercase) + 2-digit year e.g. sep25
		now := time.Now().UTC()
		mon := strings.ToLower(now.Format("Jan")) // e.g. "Sep" -> "sep"
		yr := now.Format("06")                    // 2-digit year
		c.Certificate.Name = mon + yr
	}
	if c.Certificate.Country == "" {
		c.Certificate.Country = "US"
	}
	if c.Certificate.State == "" {
		return fmt.Errorf("certificate state is required")
	}
	// City is not a valid field for Oracle SBC certificate-record, keeping for backward compatibility
	if c.Certificate.Organization == "" {
		return fmt.Errorf("certificate organization is required")
	}
	if c.Certificate.CommonName == "" {
		return fmt.Errorf("certificate common name is required")
	}
	// Set certificate defaults
	if c.Certificate.KeySize == 0 {
		c.Certificate.KeySize = 4096
	}
	if c.Certificate.KeyAlgorithm == "" {
		c.Certificate.KeyAlgorithm = "rsa"
	}
	// AlternateName defaults to empty string (no default needed)

	// Set TLS profile defaults if enabled
	if c.TLSProfile.Enabled && c.TLSProfile.ProfileName == "" {
		c.TLSProfile.ProfileName = "defaultTlsProfile"
	}
	return nil
}
