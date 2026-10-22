// vps-relay entry point.
package main

import (
	"log"
	"net/http"
)

const (
	version    = "M13"
	listenAddr = "127.0.0.1:8787"
)

func main() {
	loadKeyTable()
	mux := http.NewServeMux()
	registerAPIRoutes(mux)
	registerUIRoutes(mux)
	go autoRenewLoop()
	log.Printf("vps-relay listening on %s (%s)", listenAddr, version)
	log.Fatal(http.ListenAndServe(listenAddr, mux))
}
