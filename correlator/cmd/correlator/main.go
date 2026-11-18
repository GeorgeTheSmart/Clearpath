// Command correlator runs the Alertmanager webhook receiver.
//
//	correlator -topology topology.json -listen :8081 -agent http://agent:8000/incidents
package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/GeorgeTheSmart/clearpath/correlator/engine"
	"github.com/GeorgeTheSmart/clearpath/correlator/server"
)

func main() {
	topo := flag.String("topology", "topology.json", "JSON map service -> neighbours")
	listen := flag.String("listen", ":8081", "listen address")
	agent := flag.String("agent", "", "agent incident endpoint (empty = log only)")
	window := flag.Duration("window", 5*time.Minute, "grouping window")
	late := flag.Duration("lateness", 30*time.Second, "tolerated out-of-order arrival")
	maxFP := flag.Int("max-fingerprints", 500, "distinct fingerprints kept per incident")
	flag.Parse()

	nb := map[string][]string{}
	if b, err := os.ReadFile(*topo); err == nil {
		if err := json.Unmarshal(b, &nb); err != nil {
			log.Fatalf("topology: %v", err)
		}
	} else {
		log.Printf("no topology file (%v): grouping by service only", err)
	}
	eng := engine.New(engine.Config{Window: window.Milliseconds(), Lateness: late.Milliseconds(), MaxFingerprints: *maxFP, Neighbors: nb})
	sink := func(i engine.Incident) { b, _ := json.Marshal(i); log.Printf("incident %s", b) }
	if *agent != "" {
		sink = server.HTTPSink(*agent)
	}
	s := server.New(eng, sink, nil)
	go func() {
		for range time.Tick(5 * time.Second) {
			s.Tick()
		}
	}()
	srv := &http.Server{Addr: *listen, Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second}
	log.Printf("correlator listening on %s", *listen)
	log.Fatal(srv.ListenAndServe())
}
