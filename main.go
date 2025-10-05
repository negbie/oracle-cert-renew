package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/negbie/oracle-cert-renew/internal/config"
	"github.com/negbie/oracle-cert-renew/internal/sbc"
)

const version = "v1.1.0"

type Mode string

const (
	ModeGenerate = "generate"
	ModeImport   = "import"
	ModeCheck    = "check"
)

func main() {
	var (
		configFile  = flag.String("config", "config.yaml", "Configuration file path")
		mode        = flag.String("mode", "generate", "Operation mode: generate (CSR only), import (certificate), check (verify connection)")
		csrPath     = flag.String("csr-out", "", "Path to save generated CSR (optional, defaults to stdout if not specified)")
		certPath    = flag.String("cert_path", "", "Path to signed certificate for import (required for import mode)")
		recordName  = flag.String("record", "", "Override certificate record name from config")
		showVersion = flag.Bool("version", false, "Show version information")
		force       = flag.Bool("force", false, "Force overwrite existing certificate record")
		logStd      = flag.Bool("logstd", false, "Also log to stdout in addition to the log file")
	)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Oracle SBC Certificate Renewal Tool %s\n\n", version)
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nModes:\n")
		fmt.Fprintf(os.Stderr, "  generate     - Create certificate record and generate CSR\n")
		fmt.Fprintf(os.Stderr, "  import       - Import a signed certificate\n")
		fmt.Fprintf(os.Stderr, "  check        - Verify connection and authentication\n")

		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  # Generate CSR only\n")
		fmt.Fprintf(os.Stderr, "  %s -mode generate -csr-out sbc.csr\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  # Import signed certificate\n")
		fmt.Fprintf(os.Stderr, "  %s -mode import -cert_path sbc.crt\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  # Check connection\n")
		fmt.Fprintf(os.Stderr, "  %s -mode check\n\n", os.Args[0])
	}

	flag.Parse()

	// Initialize logging to file (always verbose behavior)
	logFile, err := os.OpenFile("oracle-cert-renew.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open log file: %v\n", err)
		os.Exit(1)
	}
	defer logFile.Close()
	// If -logstd is set, also log to stdout
	if *logStd {
		mw := io.MultiWriter(logFile, os.Stdout)
		log.SetOutput(mw)
	} else {
		log.SetOutput(logFile)
	}
	log.Printf("Oracle SBC Certificate Renewal Tool %s starting", version)

	if *showVersion {
		log.Printf("Oracle SBC Certificate Renewal Tool %s", version)
		log.Println("Copyright (c) 2024 negbie")
		return
	}

	// Validate mode
	opMode := Mode(strings.ToLower(*mode))
	switch opMode {
	case ModeGenerate, ModeImport, ModeCheck:
	default:
		log.Fatalf("Invalid mode: %s. Use 'generate', 'import', 'check', 'unlock', or 'clear-token'", *mode)
	}

	// Load configuration
	log.Printf("Loading configuration from: %s", *configFile)
	cfg, err := config.Load(*configFile)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Apply command-line overrides
	if *recordName != "" {
		cfg.Certificate.Name = *recordName
	}

	// Override paths from flags if provided
	if *csrPath != "" {
		cfg.Certificate.CSRPath = *csrPath
	}
	if *certPath != "" {
		cfg.Certificate.CertPath = *certPath
	}

	// Validate required parameters based on mode
	if opMode == ModeImport {
		if cfg.Certificate.CertPath == "" {
			log.Fatalf("Certificate path (-cert_path or config cert_path) is required for %s mode", opMode)
		}
		if _, err := os.Stat(cfg.Certificate.CertPath); err != nil {
			log.Fatalf("Certificate file not found: %v", err)
		}
	}

	// Create SBC client
	client, err := sbc.NewClient(cfg)
	if err != nil {
		log.Fatalf("Failed to create SBC client: %v", err)
	}

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	done := make(chan bool, 1)

	go func() {
		select {
		case <-sigChan:
			log.Println("Received interrupt signal, cleaning up...")
			if err := client.Close(); err != nil {
				log.Printf("Error during cleanup: %v", err)
			}
			os.Exit(1)
		case <-done:
		}
	}()

	defer func() {
		done <- true
		client.Close()
		log.Println("Shutdown complete")
	}()

	switch opMode {
	case ModeCheck:
		if err := checkConnection(client, cfg); err != nil {
			log.Fatalf("Connection check failed: %v", err)
		}
		log.Println("Connection check successful")

	case ModeGenerate:
		if err := generateCSR(client, cfg, *force); err != nil {
			log.Fatalf("CSR generation failed: %v", err)
		}
		log.Println("CSR generation completed successfully")
		if cfg.PostGenerateHook != "" {
			log.Printf("Executing post-generate-hook: %s", cfg.PostGenerateHook)
			cmd := exec.Command("sh", "-c", cfg.PostGenerateHook)
			out, err := cmd.CombinedOutput()
			if err != nil {
				log.Printf("post-generate-hook failed: %v (output: %s)", err, string(out))
			} else {
				log.Printf("post-generate-hook completed successfully")
			}
		}
	case ModeImport:
		if err := importCertificate(client, cfg, cfg.Certificate.CertPath, *force); err != nil {
			log.Fatalf("Certificate import failed: %v", err)
		}
		log.Println("Certificate import completed successfully")
	default:
		log.Fatalf("Invalid mode: %s. Use -h for help", *mode)
	}
}

// checkConnection verifies the connection and authentication with the SBC
func checkConnection(client *sbc.Client, cfg *config.Config) error {
	log.Println("Checking connection to Oracle SBC...")
	log.Printf("Host: %s:%d", cfg.SBC.Host, cfg.SBC.Port)
	log.Printf("User: %s", cfg.SBC.Username)

	if err := client.CheckConnection(); err != nil {
		return fmt.Errorf("connection check failed: %w", err)
	}

	log.Println("Authentication successful")
	log.Printf("Certificate name: %s", cfg.Certificate.Name)
	return nil
}

// generateCSR creates a certificate record and generates a CSR
func generateCSR(client *sbc.Client, cfg *config.Config, force bool) error {
	log.Printf("Starting atomic certificate record creation + CSR generation for: %s", cfg.Certificate.Name)

	// Perform the documented atomic workflow under a single lock:
	// 1) Acquire lock
	// 2) POST/PUT certificate-record
	// 3) Save / Verify / Activate
	// 4) Generate CSR
	// 5) Release lock (handled via defer in the helper)
	csr, err := client.CreateCertificateRecordAndGenerateCSR(force)
	if err != nil {
		return fmt.Errorf("atomic create+CSR operation: %w", err)
	}

	// Save or output CSR
	if cfg.Certificate.CSRPath != "" {
		if err := os.WriteFile(cfg.Certificate.CSRPath, []byte(csr), 0644); err != nil {
			return fmt.Errorf("saving CSR to file: %w", err)
		}
		log.Printf("CSR saved to: %s", cfg.Certificate.CSRPath)

	} else {
		// Log CSR if no file path specified
		log.Printf("Generated CSR (no output file specified):\n%s", csr)
	}

	log.Println("\nNext steps:")
	log.Println("1. Submit the CSR to your Certificate Authority")
	log.Println("2. After the CA returns the signed certificate, import it with:")
	log.Printf("   %s -mode import -cert_path <certificate-file>", os.Args[0])

	return nil
}

// importCertificate imports a signed certificate
func importCertificate(client *sbc.Client, cfg *config.Config, certPath string, force bool) error {
	// Reference cfg to avoid unused parameter warning and add context to logs
	log.Printf("Importing certificate for record: %s", cfg.Certificate.Name)
	if certPath == "" {
		return fmt.Errorf("certificate path not specified")
	}

	log.Printf("Importing certificate from: %s", certPath)

	// Read certificate
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("reading certificate file: %w", err)
	}

	// Import the certificate
	if err := client.ImportCertificate(string(certData), force); err != nil {
		return fmt.Errorf("importing certificate: %w", err)
	}

	log.Println("Certificate imported successfully")

	return nil
}
