package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"stash-mullvad-proxy/internal/mullvad"
	"stash-mullvad-proxy/internal/proxy"
	"stash-mullvad-proxy/internal/router"
	"stash-mullvad-proxy/internal/store"
	"stash-mullvad-proxy/internal/web"
	"stash-mullvad-proxy/internal/wireguard"
)

func main() {
	accountNumber := os.Getenv("MULLVAD_ACCOUNT")
	if accountNumber == "" {
		log.Fatal("MULLVAD_ACCOUNT environment variable is required")
	}

	dataDir := os.Getenv("DATA_DIR")
	if dataDir == "" {
		dataDir = "/data"
	}
	os.MkdirAll(dataDir, 0755)

	proxyAddr := os.Getenv("PROXY_ADDR")
	if proxyAddr == "" {
		proxyAddr = ":11001"
	}
	webAddr := os.Getenv("WEB_ADDR")
	if webAddr == "" {
		webAddr = ":11000"
	}

	// Initialize store
	dbPath := fmt.Sprintf("%s/stash-mullvad-proxy.json", dataDir)
	db, err := store.New(dbPath)
	if err != nil {
		log.Fatalf("store: %v", err)
	}
	log.Printf("store: %s", dbPath)

	// Mullvad API client
	mc := mullvad.NewClient(accountNumber)

	// WireGuard manager
	wgm := wireguard.NewManager(db, mc)
	wgm.RestoreAll()

	// Domain router
	rtr := router.New(db)

	// Forward proxy
	px := proxy.New(rtr, wgm)
	go func() {
		if err := px.ListenAndServe(proxyAddr); err != nil {
			log.Fatalf("proxy: %v", err)
		}
	}()

	// Web UI
	webHandler := web.NewHandler(db, mc, wgm, rtr)
	go func() {
		log.Printf("web ui listening on %s", webAddr)
		if err := http.ListenAndServe(webAddr, webHandler); err != nil {
			log.Fatalf("web: %v", err)
		}
	}()

	log.Println("stash-mullvad-proxy started")

	// Wait for shutdown signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	log.Printf("received %s, shutting down", s)

	wgm.Shutdown()
	log.Println("shutdown complete")
}
