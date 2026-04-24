package mullvad

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

const (
	authURL    = "https://api.mullvad.net/auth/v1/token"
	devicesURL = "https://api.mullvad.net/accounts/v1/devices"
)

type Client struct {
	accountNumber string
	accessToken   string
	tokenExpiry   time.Time
	httpClient    *http.Client
	mu            sync.Mutex
}

type tokenResponse struct {
	AccessToken string    `json:"access_token"`
	Expiry      time.Time `json:"expiry"`
}

type Device struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Pubkey      string `json:"pubkey"`
	HijackDNS  bool   `json:"hijack_dns"`
	Created     string `json:"created"`
	IPv4Address string `json:"ipv4_address"`
	IPv6Address string `json:"ipv6_address"`
}

type createDeviceRequest struct {
	Pubkey     string `json:"pubkey"`
	HijackDNS bool   `json:"hijack_dns"`
}

func NewClient(accountNumber string) *Client {
	return &Client{
		accountNumber: accountNumber,
		httpClient:    &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *Client) authenticate() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.accessToken != "" && time.Now().Before(c.tokenExpiry.Add(-5*time.Minute)) {
		return nil
	}

	body, _ := json.Marshal(map[string]string{
		"account_number": c.accountNumber,
	})

	resp, err := c.httpClient.Post(authURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("auth request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("auth failed (HTTP %d): %s", resp.StatusCode, string(b))
	}

	var tok tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return fmt.Errorf("auth decode: %w", err)
	}

	c.accessToken = tok.AccessToken
	c.tokenExpiry = tok.Expiry
	return nil
}

func (c *Client) doAuth(method, url string, payload any) (*http.Response, error) {
	if err := c.authenticate(); err != nil {
		return nil, err
	}

	var bodyReader io.Reader
	if payload != nil {
		b, _ := json.Marshal(payload)
		bodyReader = bytes.NewReader(b)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.accessToken)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	return c.httpClient.Do(req)
}

// RegisterDevice creates a new Mullvad device with the given WireGuard public key.
// Returns the device with its assigned IPv4/IPv6 addresses.
func (c *Client) RegisterDevice(pubkey string) (*Device, error) {
	resp, err := c.doAuth("POST", devicesURL, createDeviceRequest{
		Pubkey:     pubkey,
		HijackDNS: false,
	})
	if err != nil {
		return nil, fmt.Errorf("register device: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("register device (HTTP %d): %s", resp.StatusCode, string(b))
	}

	var dev Device
	if err := json.NewDecoder(resp.Body).Decode(&dev); err != nil {
		return nil, fmt.Errorf("register device decode: %w", err)
	}
	return &dev, nil
}

// RemoveDevice deletes a device from the Mullvad account.
func (c *Client) RemoveDevice(deviceID string) error {
	resp, err := c.doAuth("DELETE", devicesURL+"/"+deviceID, nil)
	if err != nil {
		return fmt.Errorf("remove device: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("remove device (HTTP %d): %s", resp.StatusCode, string(b))
	}
	return nil
}

// ListDevices returns all devices registered to the account.
func (c *Client) ListDevices() ([]Device, error) {
	resp, err := c.doAuth("GET", devicesURL, nil)
	if err != nil {
		return nil, fmt.Errorf("list devices: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("list devices (HTTP %d): %s", resp.StatusCode, string(b))
	}

	var devices []Device
	if err := json.NewDecoder(resp.Body).Decode(&devices); err != nil {
		return nil, fmt.Errorf("list devices decode: %w", err)
	}
	return devices, nil
}
