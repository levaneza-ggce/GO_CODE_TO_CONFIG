package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v2"
)

// Device credentials from vault
type DeviceCredentials struct {
	Host         string `json:"host"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	EnableSecret string `json:"enable_secret"`
	Port         int    `json:"port"`
}

// VaultClient interface for vault operations
type VaultClient interface {
	GetDeviceCredentials(deviceName string) (*DeviceCredentials, error)
}

// Simple file-based vault implementation
type FileVault struct {
	vaultFile string
}

type VaultData struct {
	Devices map[string]DeviceCredentials `json:"devices"`
}

func NewFileVault(vaultFile string) *FileVault {
	return &FileVault{vaultFile: vaultFile}
}

func (fv *FileVault) GetDeviceCredentials(deviceName string) (*DeviceCredentials, error) {
	data, err := ioutil.ReadFile(fv.vaultFile)
	if err != nil {
		return nil, fmt.Errorf("error reading vault file: %v", err)
	}

	var vaultData VaultData
	err = json.Unmarshal(data, &vaultData)
	if err != nil {
		return nil, fmt.Errorf("error parsing vault data: %v", err)
	}

	creds, exists := vaultData.Devices[deviceName]
	if !exists {
		return nil, fmt.Errorf("device '%s' not found in vault", deviceName)
	}

	if creds.Port == 0 {
		creds.Port = 22 // Default SSH port
	}

	return &creds, nil
}

// SSH Client for device connectivity
type SSHClient struct {
	config  *ssh.ClientConfig
	client  *ssh.Client
	session *ssh.Session
}

func NewSSHClient(creds *DeviceCredentials) *SSHClient {
	config := &ssh.ClientConfig{
		User: creds.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(creds.Password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         30 * time.Second,
		Config: ssh.Config{
			Ciphers: []string{
				"aes128-ctr", "aes192-ctr", "aes256-ctr",
				"aes128-gcm@openssh.com", "aes256-gcm@openssh.com",
				"chacha20-poly1305@openssh.com",
				"aes128-cbc", "aes192-cbc", "aes256-cbc", "3des-cbc",
			},
			KeyExchanges: []string{
				"curve25519-sha256", "curve25519-sha256@libssh.org",
				"ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
				"diffie-hellman-group14-sha256", "diffie-hellman-group16-sha512",
				"diffie-hellman-group18-sha512", "diffie-hellman-group14-sha1",
				"diffie-hellman-group1-sha1",
			},
			MACs: []string{
				"hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com",
				"hmac-sha2-256", "hmac-sha2-512", "hmac-sha1", "hmac-md5",
			},
		},
	}

	return &SSHClient{config: config}
}

func (sc *SSHClient) Connect(host string, port int) error {
	address := fmt.Sprintf("%s:%d", host, port)
	client, err := ssh.Dial("tcp", address, sc.config)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %v", address, err)
	}

	sc.client = client
	return nil
}

func (sc *SSHClient) ExecuteCommand(command string) (string, error) {
	if sc.client == nil {
		return "", fmt.Errorf("not connected to device")
	}

	session, err := sc.client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create session: %v", err)
	}
	defer session.Close()

	output, err := session.CombinedOutput(command)
	if err != nil {
		return "", fmt.Errorf("failed to execute command '%s': %v", command, err)
	}

	return string(output), nil
}

func (sc *SSHClient) ExecuteCommands(commands []string, enableSecret string) error {
	if sc.client == nil {
		return fmt.Errorf("not connected to device")
	}

	session, err := sc.client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session: %v", err)
	}
	defer session.Close()

	stdin, err := session.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdin pipe: %v", err)
	}

	stdout, err := session.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %v", err)
	}

	err = session.Shell()
	if err != nil {
		return fmt.Errorf("failed to start shell: %v", err)
	}

	scanner := bufio.NewScanner(stdout)
	go func() {
		for scanner.Scan() {
			fmt.Println("Device:", scanner.Text())
		}
	}()

	// Enter enable mode
	if enableSecret != "" {
		fmt.Fprintln(stdin, "enable")
		time.Sleep(1 * time.Second)
		fmt.Fprintln(stdin, enableSecret)
		time.Sleep(1 * time.Second)
	}

	// Execute commands
	for _, cmd := range commands {
		fmt.Printf("Executing: %s\n", cmd)
		fmt.Fprintln(stdin, cmd)
		time.Sleep(500 * time.Millisecond)
	}

	fmt.Fprintln(stdin, "exit")
	session.Wait()

	return nil
}

func (sc *SSHClient) GetVLANConfiguration(enableSecret string) (map[int]VLAN, error) {
	if sc.client == nil {
		return nil, fmt.Errorf("not connected to device")
	}

	session, err := sc.client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %v", err)
	}
	defer session.Close()

	stdin, err := session.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdin pipe: %v", err)
	}

	stdout, err := session.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %v", err)
	}

	err = session.Shell()
	if err != nil {
		return nil, fmt.Errorf("failed to start shell: %v", err)
	}

	var output strings.Builder
	done := make(chan bool)

	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			output.WriteString(line + "\n")
		}
		done <- true
	}()

	// Enter enable mode and execute show vlan brief
	if enableSecret != "" {
		fmt.Fprintln(stdin, "enable")
		time.Sleep(1 * time.Second)
		fmt.Fprintln(stdin, enableSecret)
		time.Sleep(1 * time.Second)
	}

	fmt.Fprintln(stdin, "show vlan brief")
	time.Sleep(2 * time.Second)
	fmt.Fprintln(stdin, "exit")

	// Wait for output
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		return nil, fmt.Errorf("timeout waiting for VLAN output")
	}

	return parseVLANOutput(output.String()), nil
}

func parseVLANOutput(output string) map[int]VLAN {
	vlans := make(map[int]VLAN)

	// Regex to match VLAN lines: ID Name Status Ports
	vlanRegex := regexp.MustCompile(`^\s*(\d+)\s+([^\s]+)\s+(active|suspend)`)

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		matches := vlanRegex.FindStringSubmatch(line)
		if len(matches) >= 3 {
			id, err := strconv.Atoi(matches[1])
			if err != nil {
				continue
			}

			// Skip default VLANs that shouldn't be managed
			if id == 1 || (id >= 1002 && id <= 1005) {
				continue
			}

			vlans[id] = VLAN{
				ID:   id,
				Name: matches[2],
			}
		}
	}

	return vlans
}

func (sc *SSHClient) Close() {
	if sc.session != nil {
		sc.session.Close()
	}
	if sc.client != nil {
		sc.client.Close()
	}
}

// VLAN represents a single VLAN configuration
type VLAN struct {
	ID          int    `yaml:"id" json:"id"`
	Name        string `yaml:"name" json:"name"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
}

// VLANConfig represents the complete VLAN configuration (YAML source of truth)
type VLANConfig struct {
	VLANs []VLAN `yaml:"vlans" json:"vlans"`
}

// DriftAnalysis represents the differences between desired and current state
type DriftAnalysis struct {
	VLANsToAdd    []VLAN
	VLANsToRemove []VLAN
	VLANsToUpdate []VLAN
	InSync        bool
}

// CiscoIOSGenerator generates Cisco IOS commands for VLAN operations
type CiscoIOSGenerator struct {
	commands []string
}

func NewCiscoIOSGenerator() *CiscoIOSGenerator {
	return &CiscoIOSGenerator{
		commands: make([]string, 0),
	}
}

func (c *CiscoIOSGenerator) AddVLAN(vlan VLAN) error {
	if vlan.ID < 1 || vlan.ID > 4094 {
		return fmt.Errorf("invalid VLAN ID %d: must be between 1 and 4094", vlan.ID)
	}

	c.commands = append(c.commands, "configure terminal")
	c.commands = append(c.commands, fmt.Sprintf("vlan %d", vlan.ID))

	if vlan.Name != "" {
		c.commands = append(c.commands, fmt.Sprintf("name %s", vlan.Name))
	}

	if vlan.Description != "" {
		c.commands = append(c.commands, fmt.Sprintf("! Description: %s", vlan.Description))
	}

	c.commands = append(c.commands, "exit")
	return nil
}

func (c *CiscoIOSGenerator) RemoveVLAN(vlan VLAN) error {
	if vlan.ID < 1 || vlan.ID > 4094 {
		return fmt.Errorf("invalid VLAN ID %d: must be between 1 and 4094", vlan.ID)
	}

	c.commands = append(c.commands, "configure terminal")
	c.commands = append(c.commands, fmt.Sprintf("no vlan %d", vlan.ID))
	return nil
}

func (c *CiscoIOSGenerator) GetCommands() []string {
	commands := make([]string, len(c.commands))
	copy(commands, c.commands)

	if len(commands) > 0 {
		commands = append(commands, "end")
		commands = append(commands, "write memory")
	}

	return commands
}

func (c *CiscoIOSGenerator) Reset() {
	c.commands = c.commands[:0]
}

// DeviceManager handles device operations with drift detection
type DeviceManager struct {
	vault VaultClient
}

func NewDeviceManager(vault VaultClient) *DeviceManager {
	return &DeviceManager{vault: vault}
}

func (dm *DeviceManager) AnalyzeDrift(deviceName string, desiredConfig *VLANConfig) (*DriftAnalysis, error) {
	// Get credentials from vault
	creds, err := dm.vault.GetDeviceCredentials(deviceName)
	if err != nil {
		return nil, fmt.Errorf("failed to get credentials for device %s: %v", deviceName, err)
	}

	fmt.Printf("Connecting to device %s at %s to analyze current state...\n", deviceName, creds.Host)

	// Create SSH client and connect
	sshClient := NewSSHClient(creds)
	err = sshClient.Connect(creds.Host, creds.Port)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to device: %v", err)
	}
	defer sshClient.Close()

	// Get current VLAN configuration from device
	currentVLANs, err := sshClient.GetVLANConfiguration(creds.EnableSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to get current VLAN configuration: %v", err)
	}

	// Convert desired config to map for easier comparison
	desiredVLANs := make(map[int]VLAN)
	for _, vlan := range desiredConfig.VLANs {
		desiredVLANs[vlan.ID] = vlan
	}

	// Analyze drift
	analysis := &DriftAnalysis{
		VLANsToAdd:    make([]VLAN, 0),
		VLANsToRemove: make([]VLAN, 0),
		VLANsToUpdate: make([]VLAN, 0),
		InSync:        true,
	}

	// Find VLANs to add or update
	for id, desiredVLAN := range desiredVLANs {
		if currentVLAN, exists := currentVLANs[id]; exists {
			// VLAN exists, check if it needs update
			if currentVLAN.Name != desiredVLAN.Name {
				analysis.VLANsToUpdate = append(analysis.VLANsToUpdate, desiredVLAN)
				analysis.InSync = false
			}
		} else {
			// VLAN doesn't exist, needs to be added
			analysis.VLANsToAdd = append(analysis.VLANsToAdd, desiredVLAN)
			analysis.InSync = false
		}
	}

	// Find VLANs to remove (exist on device but not in desired config)
	for id, currentVLAN := range currentVLANs {
		if _, exists := desiredVLANs[id]; !exists {
			analysis.VLANsToRemove = append(analysis.VLANsToRemove, currentVLAN)
			analysis.InSync = false
		}
	}

	return analysis, nil
}

func (dm *DeviceManager) ApplyConfiguration(deviceName string, analysis *DriftAnalysis) error {
	if analysis.InSync {
		fmt.Println("Device is already in sync with desired configuration.")
		return nil
	}

	// Get credentials from vault
	creds, err := dm.vault.GetDeviceCredentials(deviceName)
	if err != nil {
		return fmt.Errorf("failed to get credentials for device %s: %v", deviceName, err)
	}

	// Generate remediation commands
	generator := NewCiscoIOSGenerator()

	// Remove VLANs first
	for _, vlan := range analysis.VLANsToRemove {
		fmt.Printf("Planning to remove VLAN %d (%s)\n", vlan.ID, vlan.Name)
		if err := generator.RemoveVLAN(vlan); err != nil {
			return fmt.Errorf("error generating remove command for VLAN %d: %v", vlan.ID, err)
		}
	}

	// Add new VLANs
	for _, vlan := range analysis.VLANsToAdd {
		fmt.Printf("Planning to add VLAN %d (%s)\n", vlan.ID, vlan.Name)
		if err := generator.AddVLAN(vlan); err != nil {
			return fmt.Errorf("error generating add command for VLAN %d: %v", vlan.ID, err)
		}
	}

	// Update existing VLANs
	for _, vlan := range analysis.VLANsToUpdate {
		fmt.Printf("Planning to update VLAN %d (%s)\n", vlan.ID, vlan.Name)
		if err := generator.AddVLAN(vlan); err != nil {
			return fmt.Errorf("error generating update command for VLAN %d: %v", vlan.ID, err)
		}
	}

	commands := generator.GetCommands()
	if len(commands) == 0 {
		fmt.Println("No commands to execute.")
		return nil
	}

	fmt.Printf("Generated %d remediation commands.\n", len(commands))

	// Connect and execute commands
	fmt.Printf("Connecting to device %s at %s to apply changes...\n", deviceName, creds.Host)
	sshClient := NewSSHClient(creds)
	err = sshClient.Connect(creds.Host, creds.Port)
	if err != nil {
		return fmt.Errorf("failed to connect to device: %v", err)
	}
	defer sshClient.Close()

	fmt.Println("Applying configuration changes...")
	err = sshClient.ExecuteCommands(commands, creds.EnableSecret)
	if err != nil {
		return fmt.Errorf("failed to execute commands: %v", err)
	}

	fmt.Println("Configuration applied successfully.")
	return nil
}

// LoadConfigFromFile loads VLAN configuration from YAML file
func LoadConfigFromFile(filename string) (*VLANConfig, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("error reading file %s: %v", filename, err)
	}

	var config VLANConfig
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, fmt.Errorf("error parsing YAML file %s: %v", filename, err)
	}

	return &config, nil
}

// ValidateVLANConfig validates the VLAN configuration
func ValidateVLANConfig(config *VLANConfig) error {
	if len(config.VLANs) == 0 {
		return fmt.Errorf("no VLANs defined in configuration")
	}

	seenIDs := make(map[int]bool)

	for i, vlan := range config.VLANs {
		if vlan.ID < 1 || vlan.ID > 4094 {
			return fmt.Errorf("VLAN %d at index %d: invalid ID %d (must be 1-4094)", i+1, i, vlan.ID)
		}

		if seenIDs[vlan.ID] {
			return fmt.Errorf("VLAN %d at index %d: duplicate VLAN ID %d", i+1, i, vlan.ID)
		}
		seenIDs[vlan.ID] = true

		if strings.TrimSpace(vlan.Name) == "" {
			return fmt.Errorf("VLAN %d at index %d: name is required", i+1, i)
		}
	}

	return nil
}

func PrintUsage() {
	fmt.Println("Usage: go run VLANManagementTool.go [options] <yaml-config-file>")
	fmt.Println("")
	fmt.Println("Options:")
	fmt.Println("  -h, --help       Show this help message")
	fmt.Println("  -v, --validate   Validate configuration only")
	fmt.Println("  -d, --device     Device name to sync with (requires vault)")
	fmt.Println("  --vault          Vault file path (JSON format)")
	fmt.Println("  --check          Check drift only (don't apply changes)")
	fmt.Println("  --apply          Apply changes to make device consistent with YAML")
	fmt.Println("")
	fmt.Println("Examples:")
	fmt.Println("  go run VLANManagementTool.go --validate vlans.yaml")
	fmt.Println("  go run VLANManagementTool.go --vault vault.json -d switch1 --check vlans.yaml")
	fmt.Println("  go run VLANManagementTool.go --vault vault.json -d switch1 --apply vlans.yaml")
}

func main() {
	args := os.Args[1:]

	if len(args) == 0 {
		PrintUsage()
		os.Exit(1)
	}

	var configFile, deviceName, vaultFile string
	var validateOnly, checkOnly, apply bool

	// Parse command line arguments
	for i := 0; i < len(args); i++ {
		arg := args[i]

		switch arg {
		case "-h", "--help":
			PrintUsage()
			os.Exit(0)
		case "-v", "--validate":
			validateOnly = true
		case "--check":
			checkOnly = true
		case "--apply":
			apply = true
		case "-d", "--device":
			if i+1 >= len(args) {
				log.Fatal("Error: -d/--device requires a device name")
			}
			deviceName = args[i+1]
			i++
		case "--vault":
			if i+1 >= len(args) {
				log.Fatal("Error: --vault requires a vault file path")
			}
			vaultFile = args[i+1]
			i++
		default:
			if strings.HasPrefix(arg, "-") {
				log.Fatalf("Error: Unknown option %s", arg)
			}
			if configFile == "" {
				configFile = arg
			} else {
				log.Fatal("Error: Multiple configuration files specified")
			}
		}
	}

	if configFile == "" {
		log.Fatal("Error: No configuration file specified")
	}

	// Load and validate configuration
	fmt.Printf("Loading YAML configuration from %s...\n", configFile)
	config, err := LoadConfigFromFile(configFile)
	if err != nil {
		log.Fatalf("Error loading configuration: %v", err)
	}

	fmt.Println("Validating configuration...")
	if err := ValidateVLANConfig(config); err != nil {
		log.Fatalf("Configuration validation error: %v", err)
	}

	fmt.Printf("Configuration is valid. Found %d VLAN(s) defined.\n", len(config.VLANs))

	if validateOnly {
		fmt.Println("Validation completed successfully.")
		return
	}

	// Device operations require vault
	if deviceName != "" {
		if vaultFile == "" {
			log.Fatal("Error: --vault is required when using -d/--device")
		}

		vault := NewFileVault(vaultFile)
		deviceManager := NewDeviceManager(vault)

		// Analyze drift
		fmt.Println("Analyzing configuration drift...")
		analysis, err := deviceManager.AnalyzeDrift(deviceName, config)
		if err != nil {
			log.Fatalf("Error analyzing drift: %v", err)
		}

		// Print drift analysis
		if analysis.InSync {
			fmt.Println("✓ Device configuration is in sync with YAML.")
		} else {
			fmt.Println("✗ Device configuration drift detected:")

			if len(analysis.VLANsToAdd) > 0 {
				fmt.Printf("  VLANs to ADD (%d):\n", len(analysis.VLANsToAdd))
				for _, vlan := range analysis.VLANsToAdd {
					fmt.Printf("    - VLAN %d: %s\n", vlan.ID, vlan.Name)
				}
			}

			if len(analysis.VLANsToUpdate) > 0 {
				fmt.Printf("  VLANs to UPDATE (%d):\n", len(analysis.VLANsToUpdate))
				for _, vlan := range analysis.VLANsToUpdate {
					fmt.Printf("    - VLAN %d: %s\n", vlan.ID, vlan.Name)
				}
			}

			if len(analysis.VLANsToRemove) > 0 {
				fmt.Printf("  VLANs to REMOVE (%d):\n", len(analysis.VLANsToRemove))
				for _, vlan := range analysis.VLANsToRemove {
					fmt.Printf("    - VLAN %d: %s\n", vlan.ID, vlan.Name)
				}
			}
		}

		// Apply changes if requested
		if apply && !analysis.InSync {
			fmt.Println("\nApplying configuration changes...")
			err = deviceManager.ApplyConfiguration(deviceName, analysis)
			if err != nil {
				log.Fatalf("Error applying configuration: %v", err)
			}
		} else if checkOnly || analysis.InSync {
			fmt.Println("Use --apply to remediate the drift.")
		}

		return
	}

	// If no device specified, just show what the YAML contains
	fmt.Println("\nDesired VLAN Configuration (from YAML):")
	fmt.Println("======================================")
	for _, vlan := range config.VLANs {
		fmt.Printf("VLAN %d: %s", vlan.ID, vlan.Name)
		if vlan.Description != "" {
			fmt.Printf(" (%s)", vlan.Description)
		}
		fmt.Println()
	}
}
