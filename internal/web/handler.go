package web

import (
	_ "embed"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"

	"stash-mullvad-proxy/internal/mullvad"
	"stash-mullvad-proxy/internal/router"
	"stash-mullvad-proxy/internal/store"
	"stash-mullvad-proxy/internal/wireguard"
)

//go:embed static/index.html
var indexHTML []byte

type Handler struct {
	store     *store.Store
	mullvad   *mullvad.Client
	relays    *mullvad.RelayCache
	wgManager *wireguard.Manager
	router    *router.Router
	mux       *http.ServeMux
}

func NewHandler(s *store.Store, mc *mullvad.Client, wg *wireguard.Manager, r *router.Router) *Handler {
	h := &Handler{
		store:     s,
		mullvad:   mc,
		relays:    mullvad.NewRelayCache(),
		wgManager: wg,
		router:    r,
		mux:       http.NewServeMux(),
	}

	h.mux.HandleFunc("GET /api/relays", h.getRelays)
	h.mux.HandleFunc("GET /api/tunnels", h.getTunnels)
	h.mux.HandleFunc("POST /api/tunnels", h.createTunnel)
	h.mux.HandleFunc("DELETE /api/tunnels/{id}", h.deleteTunnel)
	h.mux.HandleFunc("GET /api/routes", h.getRoutes)
	h.mux.HandleFunc("POST /api/routes", h.createRoute)
	h.mux.HandleFunc("DELETE /api/routes/{id}", h.deleteRoute)
	h.mux.HandleFunc("GET /api/status", h.getStatus)
	h.mux.HandleFunc("GET /", h.serveUI)

	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

// --- Relays ---

func (h *Handler) getRelays(w http.ResponseWriter, r *http.Request) {
	relays, err := h.relays.GetRelays()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, relays)
}

// --- Tunnels ---

type createTunnelReq struct {
	Name          string `json:"name"`
	RelayHostname string `json:"relay_hostname"`
}

func (h *Handler) getTunnels(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.wgManager.GetAllStatus())
}

func (h *Handler) createTunnel(w http.ResponseWriter, r *http.Request) {
	var req createTunnelReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if req.Name == "" || req.RelayHostname == "" {
		writeErr(w, http.StatusBadRequest, "name and relay_hostname required")
		return
	}

	// Look up the relay
	relays, err := h.relays.GetRelays()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to fetch relays: "+err.Error())
		return
	}
	var relay *mullvad.Relay
	for i := range relays {
		if relays[i].Hostname == req.RelayHostname {
			relay = &relays[i]
			break
		}
	}
	if relay == nil {
		writeErr(w, http.StatusBadRequest, "relay not found: "+req.RelayHostname)
		return
	}

	tunnel, err := h.wgManager.CreateTunnel(*relay, req.Name)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to create tunnel: "+err.Error())
		return
	}

	// Return sanitized tunnel (no private key)
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":             tunnel.ID,
		"name":           tunnel.Name,
		"relay_hostname": tunnel.RelayHostname,
		"country_name":   tunnel.CountryName,
		"city_name":      tunnel.CityName,
		"assigned_ipv4":  tunnel.AssignedIPv4,
	})
}

func (h *Handler) deleteTunnel(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid tunnel id")
		return
	}

	// Check if any routes reference this tunnel
	for _, route := range h.store.GetAllRoutes() {
		if route.TunnelID == id {
			writeErr(w, http.StatusConflict, "tunnel has active routes; delete them first")
			return
		}
	}

	if err := h.wgManager.RemoveTunnel(id); err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeErr(w, http.StatusNotFound, err.Error())
		} else {
			writeErr(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	h.router.Reload()
	w.WriteHeader(http.StatusNoContent)
}

// --- Routes ---

type createRouteReq struct {
	DomainPattern string `json:"domain_pattern"`
	TunnelID      int    `json:"tunnel_id"`
}

type routeResponse struct {
	ID            int    `json:"id"`
	DomainPattern string `json:"domain_pattern"`
	TunnelID      int    `json:"tunnel_id"`
	TunnelName    string `json:"tunnel_name"`
}

func (h *Handler) getRoutes(w http.ResponseWriter, r *http.Request) {
	routes := h.store.GetAllRoutes()
	out := make([]routeResponse, len(routes))
	for i, rt := range routes {
		out[i] = routeResponse{
			ID:            rt.ID,
			DomainPattern: rt.DomainPattern,
			TunnelID:      rt.TunnelID,
			TunnelName:    h.store.TunnelName(rt.TunnelID),
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) createRoute(w http.ResponseWriter, r *http.Request) {
	var req createRouteReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if req.DomainPattern == "" || req.TunnelID == 0 {
		writeErr(w, http.StatusBadRequest, "domain_pattern and tunnel_id required")
		return
	}

	route := &store.Route{
		DomainPattern: strings.ToLower(strings.TrimSpace(req.DomainPattern)),
		TunnelID:      req.TunnelID,
	}

	id, err := h.store.CreateRoute(route)
	if err != nil {
		if strings.Contains(err.Error(), "already exists") || strings.Contains(err.Error(), "not found") {
			writeErr(w, http.StatusConflict, err.Error())
		} else {
			writeErr(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	route.ID = id

	h.router.Reload()
	log.Printf("route added: %s → tunnel %d", route.DomainPattern, route.TunnelID)

	writeJSON(w, http.StatusCreated, routeResponse{
		ID:            route.ID,
		DomainPattern: route.DomainPattern,
		TunnelID:      route.TunnelID,
		TunnelName:    h.store.TunnelName(route.TunnelID),
	})
}

func (h *Handler) deleteRoute(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid route id")
		return
	}

	if err := h.store.DeleteRoute(id); err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeErr(w, http.StatusNotFound, err.Error())
		} else {
			writeErr(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	h.router.Reload()
	w.WriteHeader(http.StatusNoContent)
}

// --- Status ---

type statusResponse struct {
	ActiveTunnels int    `json:"active_tunnels"`
	TotalRoutes   int    `json:"total_routes"`
	ProxyAddr     string `json:"proxy_addr"`
}

func (h *Handler) getStatus(w http.ResponseWriter, r *http.Request) {
	tunnels := h.wgManager.GetAllStatus()
	active := 0
	for _, t := range tunnels {
		if t.Up {
			active++
		}
	}

	writeJSON(w, http.StatusOK, statusResponse{
		ActiveTunnels: active,
		TotalRoutes:   len(h.store.GetAllRoutes()),
		ProxyAddr:     ":11001",
	})
}

// --- UI ---

func (h *Handler) serveUI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(indexHTML)
}

// --- helpers ---

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
