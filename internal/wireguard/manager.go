package wireguard

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"stash-mullvad-proxy/internal/mullvad"
	"stash-mullvad-proxy/internal/store"
)

type ActiveTunnel struct {
	store.Tunnel
	InterfaceName string
	LocalIP       string // IP without CIDR suffix
}

type TunnelStatus struct {
	ID            int        `json:"id"`
	Name          string     `json:"name"`
	RelayHostname string     `json:"relay_hostname"`
	CountryName   string     `json:"country_name"`
	CityName      string     `json:"city_name"`
	InterfaceName string     `json:"interface_name"`
	LocalIP       string     `json:"local_ip"`
	Up            bool       `json:"up"`
	Connected     bool       `json:"connected"`
	LastHandshake *time.Time `json:"last_handshake,omitempty"`
}

type Manager struct {
	store   *store.Store
	mullvad *mullvad.Client
	tunnels map[int]*ActiveTunnel
	mu      sync.RWMutex
}

func NewManager(s *store.Store, mc *mullvad.Client) *Manager {
	return &Manager{
		store:   s,
		mullvad: mc,
		tunnels: make(map[int]*ActiveTunnel),
	}
}

// GenerateKeyPair shells out to wg to create a Curve25519 keypair.
func GenerateKeyPair() (privateKey, publicKey string, err error) {
	privOut, err := exec.Command("wg", "genkey").Output()
	if err != nil {
		return "", "", fmt.Errorf("wg genkey: %w", err)
	}
	privateKey = strings.TrimSpace(string(privOut))

	cmd := exec.Command("wg", "pubkey")
	cmd.Stdin = strings.NewReader(privateKey)
	pubOut, err := cmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("wg pubkey: %w", err)
	}
	publicKey = strings.TrimSpace(string(pubOut))

	return privateKey, publicKey, nil
}

// CreateTunnel generates a keypair, registers with Mullvad, creates the WireGuard
// interface, and sets up policy routing.
func (m *Manager) CreateTunnel(relay mullvad.Relay, name string) (*store.Tunnel, error) {
	privKey, pubKey, err := GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("keygen: %w", err)
	}

	device, err := m.mullvad.RegisterDevice(pubKey)
	if err != nil {
		return nil, fmt.Errorf("mullvad register: %w", err)
	}

	tunnel := &store.Tunnel{
		Name:          name,
		RelayHostname: relay.Hostname,
		CountryName:   relay.CountryName,
		CityName:      relay.CityName,
		DeviceID:      device.ID,
		PrivateKey:    privKey,
		PublicKey:     pubKey,
		AssignedIPv4:  device.IPv4Address, // CIDR, e.g. 10.0.19.123/32
		AssignedIPv6:  device.IPv6Address,
		RelayPubkey:   relay.Pubkey,
		RelayIPv4:     relay.IPv4AddrIn,
		RelayPort:     51820,
		Active:        false,
	}

	id, err := m.store.CreateTunnel(tunnel)
	if err != nil {
		m.mullvad.RemoveDevice(device.ID)
		return nil, fmt.Errorf("store: %w", err)
	}
	tunnel.ID = id

	if err := m.activate(tunnel); err != nil {
		m.store.DeleteTunnel(id)
		m.mullvad.RemoveDevice(device.ID)
		return nil, fmt.Errorf("activate: %w", err)
	}

	return tunnel, nil
}

// RemoveTunnel tears down the interface, removes the Mullvad device, and deletes from store.
func (m *Manager) RemoveTunnel(id int) error {
	tunnel, err := m.store.GetTunnel(id)
	if err != nil {
		return err
	}

	m.deactivate(tunnel)

	if tunnel.DeviceID != "" {
		if err := m.mullvad.RemoveDevice(tunnel.DeviceID); err != nil {
			log.Printf("warning: failed to remove Mullvad device %s: %v", tunnel.DeviceID, err)
		}
	}

	return m.store.DeleteTunnel(id)
}

// GetActiveTunnel returns the in-memory state for an active tunnel.
func (m *Manager) GetActiveTunnel(id int) *ActiveTunnel {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.tunnels[id]
}

// GetAllStatus returns status for every stored tunnel.
func (m *Manager) GetAllStatus() []TunnelStatus {
	all := m.store.GetAllTunnels()
	out := make([]TunnelStatus, 0, len(all))

	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, t := range all {
		st := TunnelStatus{
			ID:            t.ID,
			Name:          t.Name,
			RelayHostname: t.RelayHostname,
			CountryName:   t.CountryName,
			CityName:      t.CityName,
		}

		if at, ok := m.tunnels[t.ID]; ok {
			st.InterfaceName = at.InterfaceName
			st.LocalIP = at.LocalIP
			st.Up = true
			st.Connected, st.LastHandshake = checkHandshake(at.InterfaceName)
		}

		out = append(out, st)
	}
	return out
}

// RestoreAll re-activates tunnels that were marked active in the store.
// Called on startup to survive container restarts.
func (m *Manager) RestoreAll() {
	for _, t := range m.store.GetActiveTunnels() {
		if err := m.activate(t); err != nil {
			log.Printf("restore tunnel %d (%s): %v", t.ID, t.Name, err)
			m.store.SetTunnelActive(t.ID, false)
		} else {
			log.Printf("restored tunnel %d (%s) on %s", t.ID, t.Name, fmt.Sprintf("wg%d", t.ID))
		}
	}
}

// Shutdown tears down all active WireGuard interfaces.
func (m *Manager) Shutdown() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, at := range m.tunnels {
		exec.Command("ip", "link", "del", at.InterfaceName).Run()
	}
}

// --- internal ---

func (m *Manager) activate(t *store.Tunnel) error {
	ifName := fmt.Sprintf("wg%d", t.ID)
	tableNum := strconv.Itoa(100 + t.ID)

	// Parse local IP from CIDR
	localIP := t.AssignedIPv4
	if idx := strings.Index(localIP, "/"); idx != -1 {
		localIP = localIP[:idx]
	}
	cidr := t.AssignedIPv4
	if !strings.Contains(cidr, "/") {
		cidr += "/32"
	}

	// Write private key to temp file
	keyFile, err := os.CreateTemp("", "wg-key-*")
	if err != nil {
		return fmt.Errorf("create keyfile: %w", err)
	}
	keyPath := keyFile.Name()
	defer os.Remove(keyPath)
	keyFile.WriteString(t.PrivateKey)
	keyFile.Close()
	os.Chmod(keyPath, 0600)

	// Create interface
	if err := run("ip", "link", "add", ifName, "type", "wireguard"); err != nil {
		return fmt.Errorf("create interface: %w", err)
	}

	// Configure WireGuard peer
	if err := run("wg", "set", ifName,
		"private-key", keyPath,
		"peer", t.RelayPubkey,
		"endpoint", fmt.Sprintf("%s:%d", t.RelayIPv4, t.RelayPort),
		"allowed-ips", "0.0.0.0/0,::/0",
	); err != nil {
		run("ip", "link", "del", ifName)
		return fmt.Errorf("configure wg: %w", err)
	}

	// Assign IP
	if err := run("ip", "addr", "add", cidr, "dev", ifName); err != nil {
		run("ip", "link", "del", ifName)
		return fmt.Errorf("assign ip: %w", err)
	}

	// Bring up
	if err := run("ip", "link", "set", ifName, "up"); err != nil {
		run("ip", "link", "del", ifName)
		return fmt.Errorf("link up: %w", err)
	}

	// Policy routing: packets from this tunnel's IP go through its own routing table
	run("ip", "rule", "add", "from", localIP, "table", tableNum)
	run("ip", "route", "add", "default", "dev", ifName, "table", tableNum)

	m.mu.Lock()
	m.tunnels[t.ID] = &ActiveTunnel{
		Tunnel:        *t,
		InterfaceName: ifName,
		LocalIP:       localIP,
	}
	m.mu.Unlock()

	m.store.SetTunnelActive(t.ID, true)
	log.Printf("activated tunnel %d (%s) via %s → %s:%d", t.ID, t.Name, ifName, t.RelayIPv4, t.RelayPort)
	return nil
}

func (m *Manager) deactivate(t *store.Tunnel) {
	ifName := fmt.Sprintf("wg%d", t.ID)
	tableNum := strconv.Itoa(100 + t.ID)

	localIP := t.AssignedIPv4
	if idx := strings.Index(localIP, "/"); idx != -1 {
		localIP = localIP[:idx]
	}

	run("ip", "rule", "del", "from", localIP, "table", tableNum)
	run("ip", "route", "del", "default", "dev", ifName, "table", tableNum)
	run("ip", "link", "del", ifName)

	m.mu.Lock()
	delete(m.tunnels, t.ID)
	m.mu.Unlock()

	m.store.SetTunnelActive(t.ID, false)
	log.Printf("deactivated tunnel %d (%s)", t.ID, t.Name)
}

func checkHandshake(ifName string) (connected bool, lastHS *time.Time) {
	out, err := exec.Command("wg", "show", ifName, "latest-handshakes").Output()
	if err != nil {
		return false, nil
	}

	// Output: "<pubkey>\t<unix_timestamp>\n"
	fields := strings.Fields(strings.TrimSpace(string(out)))
	if len(fields) < 2 {
		return false, nil
	}
	ts, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil || ts == 0 {
		return false, nil
	}
	t := time.Unix(ts, 0)
	return time.Since(t) < 3*time.Minute, &t
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %s: %w", name, strings.Join(args, " "), strings.TrimSpace(string(out)), err)
	}
	return nil
}
