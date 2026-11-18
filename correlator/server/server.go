// Package server exposes the engine as an Alertmanager webhook receiver.
package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/GeorgeTheSmart/clearpath/correlator/engine"
)

// amPayload is the subset of the Alertmanager webhook (version 4) we use.
type amPayload struct {
	Version string `json:"version"`
	Alerts  []struct {
		Status      string            `json:"status"`
		Labels      map[string]string `json:"labels"`
		Annotations map[string]string `json:"annotations"`
		Fingerprint string            `json:"fingerprint"`
	} `json:"alerts"`
}

// Sink receives closed incidents (the agent's HTTP endpoint in production).
type Sink func(engine.Incident)

// Server serialises engine access behind a mutex; one engine call is ~1 µs,
// so a single lock is not the bottleneck at the target load (see bench).
type Server struct {
	mu   sync.Mutex
	eng  *engine.Engine
	sink Sink
	now  func() int64
}

func New(eng *engine.Engine, sink Sink, now func() int64) *Server {
	if now == nil {
		now = func() int64 { return time.Now().UnixMilli() }
	}
	return &Server{eng: eng, sink: sink, now: now}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/alerts", s.alerts)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	mux.HandleFunc("/metrics", s.metrics)
	return mux
}

func (s *Server) alerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
	var p amPayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, "bad payload: "+err.Error(), http.StatusBadRequest)
		return
	}
	ts := s.now()
	var closed []engine.Incident
	s.mu.Lock()
	for _, a := range p.Alerts {
		if a.Status == "resolved" {
			continue
		}
		svc := a.Labels["service"]
		if svc == "" {
			svc = a.Labels["job"]
		}
		closed = append(closed, s.eng.Ingest(engine.Alert{
			Fingerprint: a.Fingerprint, Name: a.Labels["alertname"], Service: svc,
			Severity: a.Labels["severity"], TS: ts,
		})...)
	}
	s.mu.Unlock()
	for _, inc := range closed {
		s.sink(inc)
	}
	w.WriteHeader(http.StatusAccepted)
}

// Tick advances the watermark from the wall clock so quiet incidents still close.
func (s *Server) Tick() {
	s.mu.Lock()
	closed := s.eng.Advance(s.now())
	s.mu.Unlock()
	for _, inc := range closed {
		s.sink(inc)
	}
}

func (s *Server) metrics(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	st := s.eng.Stats()
	s.mu.Unlock()
	fmt.Fprintf(w, "# TYPE correlator_alerts_ingested_total counter\ncorrelator_alerts_ingested_total %d\n", st.Ingested)
	fmt.Fprintf(w, "# TYPE correlator_alerts_late_total counter\ncorrelator_alerts_late_total %d\n", st.Late)
	fmt.Fprintf(w, "# TYPE correlator_incidents_emitted_total counter\ncorrelator_incidents_emitted_total %d\n", st.Emitted)
	fmt.Fprintf(w, "# TYPE correlator_suppressed_occurrences_total counter\ncorrelator_suppressed_occurrences_total %d\n", st.SuppressedOccs)
	fmt.Fprintf(w, "# TYPE correlator_live_segments gauge\ncorrelator_live_segments %d\n", st.LiveSegments)
	fmt.Fprintf(w, "# TYPE correlator_open_incidents gauge\ncorrelator_open_incidents %d\n", st.OpenIncidents)
}

// HTTPSink posts incidents to the agent with bounded retries.
func HTTPSink(url string) Sink {
	client := &http.Client{Timeout: 5 * time.Second}
	return func(inc engine.Incident) {
		body, _ := json.Marshal(inc)
		for attempt := 0; attempt < 3; attempt++ {
			resp, err := client.Post(url, "application/json", bytes.NewReader(body))
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode < 300 {
					return
				}
			}
			time.Sleep(time.Duration(200*(1<<attempt)) * time.Millisecond)
		}
		log.Printf("dropping incident %s after retries", inc.ID)
	}
}
