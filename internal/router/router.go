package router

import (
	"strings"
	"sync"

	"stash-mullvad-proxy/internal/store"
)

type Router struct {
	store  *store.Store
	routes []*store.Route
	mu     sync.RWMutex
}

func New(s *store.Store) *Router {
	r := &Router{store: s}
	r.Reload()
	return r
}

// Reload refreshes the in-memory route table from the store.
func (r *Router) Reload() {
	routes := r.store.GetAllRoutes()
	r.mu.Lock()
	r.routes = routes
	r.mu.Unlock()
}

// Match returns the tunnel ID for the first matching route, or 0 if none match.
func (r *Router) Match(domain string) (tunnelID int, matched bool) {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))

	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, route := range r.routes {
		if matchDomain(strings.ToLower(route.DomainPattern), domain) {
			return route.TunnelID, true
		}
	}
	return 0, false
}

// matchDomain supports:
//   - exact: "example.com"
//   - wildcard prefix: "*.example.com" matches "foo.example.com", "bar.baz.example.com"
//   - bare wildcard with dot: ".example.com" same as *.example.com
func matchDomain(pattern, domain string) bool {
	if pattern == domain {
		return true
	}

	// *.example.com → matches any subdomain of example.com
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".example.com"
		return strings.HasSuffix(domain, suffix)
	}

	// .example.com → same as *.example.com
	if strings.HasPrefix(pattern, ".") {
		return strings.HasSuffix(domain, pattern) || domain == pattern[1:]
	}

	return false
}
