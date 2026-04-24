package store

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

type Tunnel struct {
	ID            int    `json:"id"`
	Name          string `json:"name"`
	RelayHostname string `json:"relay_hostname"`
	CountryName   string `json:"country_name"`
	CityName      string `json:"city_name"`
	DeviceID      string `json:"device_id"`
	PrivateKey    string `json:"private_key"`
	PublicKey     string `json:"public_key"`
	AssignedIPv4  string `json:"assigned_ipv4"` // CIDR, e.g. 10.0.19.123/32
	AssignedIPv6  string `json:"assigned_ipv6"`
	RelayPubkey   string `json:"relay_pubkey"`
	RelayIPv4     string `json:"relay_ipv4"`
	RelayPort     int    `json:"relay_port"`
	Active        bool   `json:"active"`
}

type Route struct {
	ID            int    `json:"id"`
	DomainPattern string `json:"domain_pattern"`
	TunnelID      int    `json:"tunnel_id"`
}

type data struct {
	Tunnels      []*Tunnel `json:"tunnels"`
	Routes       []*Route  `json:"routes"`
	NextTunnelID int       `json:"next_tunnel_id"`
	NextRouteID  int       `json:"next_route_id"`
}

type Store struct {
	path string
	d    data
	mu   sync.RWMutex
}

func New(path string) (*Store, error) {
	s := &Store{
		path: path,
		d: data{
			NextTunnelID: 1,
			NextRouteID:  1,
		},
	}

	raw, err := os.ReadFile(path)
	if err == nil {
		if err := json.Unmarshal(raw, &s.d); err != nil {
			return nil, fmt.Errorf("parse store %s: %w", path, err)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read store %s: %w", path, err)
	}

	return s, nil
}

func (s *Store) save() error {
	raw, err := json.MarshalIndent(s.d, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// --- Tunnels ---

func (s *Store) CreateTunnel(t *Tunnel) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	t.ID = s.d.NextTunnelID
	s.d.NextTunnelID++
	s.d.Tunnels = append(s.d.Tunnels, t)

	if err := s.save(); err != nil {
		// Roll back
		s.d.Tunnels = s.d.Tunnels[:len(s.d.Tunnels)-1]
		s.d.NextTunnelID--
		return 0, err
	}
	return t.ID, nil
}

func (s *Store) GetTunnel(id int) (*Tunnel, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, t := range s.d.Tunnels {
		if t.ID == id {
			return t, nil
		}
	}
	return nil, fmt.Errorf("tunnel %d not found", id)
}

func (s *Store) GetAllTunnels() []*Tunnel {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]*Tunnel, len(s.d.Tunnels))
	copy(out, s.d.Tunnels)
	return out
}

func (s *Store) GetActiveTunnels() []*Tunnel {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var out []*Tunnel
	for _, t := range s.d.Tunnels {
		if t.Active {
			out = append(out, t)
		}
	}
	return out
}

func (s *Store) SetTunnelActive(id int, active bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, t := range s.d.Tunnels {
		if t.ID == id {
			t.Active = active
			return s.save()
		}
	}
	return fmt.Errorf("tunnel %d not found", id)
}

func (s *Store) DeleteTunnel(id int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	idx := -1
	for i, t := range s.d.Tunnels {
		if t.ID == id {
			idx = i
			break
		}
	}
	if idx == -1 {
		return fmt.Errorf("tunnel %d not found", id)
	}

	// Remove routes pointing to this tunnel
	var kept []*Route
	for _, r := range s.d.Routes {
		if r.TunnelID != id {
			kept = append(kept, r)
		}
	}
	s.d.Routes = kept

	s.d.Tunnels = append(s.d.Tunnels[:idx], s.d.Tunnels[idx+1:]...)
	return s.save()
}

// --- Routes ---

func (s *Store) CreateRoute(r *Route) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check for duplicate domain pattern
	for _, existing := range s.d.Routes {
		if existing.DomainPattern == r.DomainPattern {
			return 0, fmt.Errorf("route for %q already exists", r.DomainPattern)
		}
	}

	// Verify tunnel exists
	found := false
	for _, t := range s.d.Tunnels {
		if t.ID == r.TunnelID {
			found = true
			break
		}
	}
	if !found {
		return 0, fmt.Errorf("tunnel %d not found", r.TunnelID)
	}

	r.ID = s.d.NextRouteID
	s.d.NextRouteID++
	s.d.Routes = append(s.d.Routes, r)

	if err := s.save(); err != nil {
		s.d.Routes = s.d.Routes[:len(s.d.Routes)-1]
		s.d.NextRouteID--
		return 0, err
	}
	return r.ID, nil
}

func (s *Store) GetAllRoutes() []*Route {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]*Route, len(s.d.Routes))
	copy(out, s.d.Routes)
	return out
}

func (s *Store) DeleteRoute(id int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, r := range s.d.Routes {
		if r.ID == id {
			s.d.Routes = append(s.d.Routes[:i], s.d.Routes[i+1:]...)
			return s.save()
		}
	}
	return fmt.Errorf("route %d not found", id)
}

// TunnelName returns a display name for use in route listings.
func (s *Store) TunnelName(id int) string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, t := range s.d.Tunnels {
		if t.ID == id {
			return t.Name
		}
	}
	return "unknown"
}
