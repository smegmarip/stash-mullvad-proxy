package mullvad

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

const relaysURL = "https://api.mullvad.net/www/relays/wireguard/"

type Relay struct {
	Hostname         string `json:"hostname"`
	CountryCode      string `json:"country_code"`
	CountryName      string `json:"country_name"`
	CityCode         string `json:"city_code"`
	CityName         string `json:"city_name"`
	FQDN             string `json:"fqdn"`
	Active           bool   `json:"active"`
	Owned            bool   `json:"owned"`
	Provider         string `json:"provider"`
	IPv4AddrIn       string `json:"ipv4_addr_in"`
	IPv6AddrIn       string `json:"ipv6_addr_in"`
	NetworkPortSpeed int    `json:"network_port_speed"`
	Pubkey           string `json:"pubkey"`
	MultihopPort     int    `json:"multihop_port"`
	Type             string `json:"type"`
	DAITA            bool   `json:"daita"`
}

type RelayCache struct {
	relays    []Relay
	fetchedAt time.Time
	mu        sync.RWMutex
	ttl       time.Duration
}

func NewRelayCache() *RelayCache {
	return &RelayCache{ttl: 1 * time.Hour}
}

func (rc *RelayCache) GetRelays() ([]Relay, error) {
	rc.mu.RLock()
	if rc.relays != nil && time.Since(rc.fetchedAt) < rc.ttl {
		out := make([]Relay, len(rc.relays))
		copy(out, rc.relays)
		rc.mu.RUnlock()
		return out, nil
	}
	rc.mu.RUnlock()

	return rc.refresh()
}

func (rc *RelayCache) refresh() ([]Relay, error) {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	// Double-check after acquiring write lock
	if rc.relays != nil && time.Since(rc.fetchedAt) < rc.ttl {
		out := make([]Relay, len(rc.relays))
		copy(out, rc.relays)
		return out, nil
	}

	resp, err := http.Get(relaysURL)
	if err != nil {
		if rc.relays != nil {
			return rc.relays, nil // return stale on error
		}
		return nil, err
	}
	defer resp.Body.Close()

	var relays []Relay
	if err := json.NewDecoder(resp.Body).Decode(&relays); err != nil {
		if rc.relays != nil {
			return rc.relays, nil
		}
		return nil, err
	}

	// Keep only active relays
	active := make([]Relay, 0, len(relays)/2)
	for _, r := range relays {
		if r.Active {
			active = append(active, r)
		}
	}

	rc.relays = active
	rc.fetchedAt = time.Now()

	out := make([]Relay, len(active))
	copy(out, active)
	return out, nil
}
