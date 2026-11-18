// Command bench measures correlator throughput, per-alert latency and memory
// under synthetic alert storms and writes JSON results.
//
//	go run ./cmd/bench -out ../eval/results/bench_correlator.json
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"sort"
	"time"

	"github.com/GeorgeTheSmart/clearpath/correlator/engine"
	"github.com/GeorgeTheSmart/clearpath/correlator/server"
)

type result struct {
	Scenario         string  `json:"scenario"`
	Services         int     `json:"services"`
	Alerts           int     `json:"alerts"`
	EventRatePerMin  float64 `json:"event_rate_per_min"`
	DistinctFPs      int     `json:"distinct_fingerprints"`
	ThroughputPerSec float64 `json:"throughput_alerts_per_sec"`
	P50us            float64 `json:"p50_us"`
	P99us            float64 `json:"p99_us"`
	P999us           float64 `json:"p999_us"`
	MaxUs            float64 `json:"max_us"`
	PeakHeapMB       float64 `json:"peak_heap_mb"`
	Incidents        int     `json:"incidents"`
	NoisePerSvcHour  float64 `json:"noise_alerts_per_service_per_hour"`
	CrossWindowSec   float64 `json:"cross_window_s"`
	PercThresholdPc  float64 `json:"site_percolation_threshold_pc"`
	PredictedNuCrit  float64 `json:"predicted_critical_noise_per_service_hour"`
	LargestShare     float64 `json:"largest_incident_share_of_alerts"`
	TotalConserved   bool    `json:"total_conserved"`
	HTTPAlertsPerSec float64 `json:"http_alerts_per_sec,omitempty"`
	HTTPBatchSize    int     `json:"http_batch_size,omitempty"`
}

func topology(r *rand.Rand, n, deg int) ([]string, map[string][]string) {
	svcs := make([]string, n)
	for i := range svcs {
		svcs[i] = fmt.Sprintf("svc-%03d", i)
	}
	nb := map[string][]string{}
	for i := 1; i < n; i++ { // random tree + extra edges, like a call graph
		j := r.Intn(i)
		nb[svcs[i]] = append(nb[svcs[i]], svcs[j])
		nb[svcs[j]] = append(nb[svcs[j]], svcs[i])
	}
	for k := 0; k < n*(deg-2)/2; k++ {
		a, b := r.Intn(n), r.Intn(n)
		if a != b {
			nb[svcs[a]] = append(nb[svcs[a]], svcs[b])
			nb[svcs[b]] = append(nb[svcs[b]], svcs[a])
		}
	}
	return svcs, nb
}

// storm: a storm on a few failing services at perMin, plus independent
// background noise at nu alerts per service per hour (Poisson, fleet-wide).
// Fingerprints are per (alertname, service, pod) so storms have many distinct fps.
func storm(r *rand.Rand, svcs []string, n int, perMin float64, pods int, nu float64) []engine.Alert {
	names := []string{"HighErrorRate", "HighLatencyP99", "PodCrashLooping", "HighCPU", "TargetDown"}
	noisePerMin := nu * float64(len(svcs)) / 60
	totalPerMin := perMin + noisePerMin
	gapMs := 60_000.0 / totalPerMin
	out := make([]engine.Alert, n)
	t := 0.0
	hot := svcs[r.Intn(len(svcs))]
	for i := range out {
		t += r.ExpFloat64() * gapMs
		if r.Float64() < 0.0005 { // the storm moves to another failing service
			hot = svcs[r.Intn(len(svcs))]
		}
		s := hot
		if r.Float64() < noisePerMin/totalPerMin {
			s = svcs[r.Intn(len(svcs))]
		}
		nm := names[r.Intn(len(names))]
		pod := r.Intn(pods)
		out[i] = engine.Alert{Fingerprint: fmt.Sprintf("%s|%s|%d", nm, s, pod), Name: nm, Service: s, TS: int64(t)}
	}
	// bounded disorder (network jitter up to 2 s)
	type k struct {
		key float64
		a   engine.Alert
	}
	ks := make([]k, n)
	for i, a := range out {
		ks[i] = k{float64(a.TS) + r.Float64()*2000, a}
	}
	sort.Slice(ks, func(i, j int) bool { return ks[i].key < ks[j].key })
	for i := range ks {
		out[i] = ks[i].a
	}
	return out
}

// percolationThreshold returns the configuration-model site-percolation
// threshold p_c = <k>/(<k^2>-<k>) for the generated topology.
func percolationThreshold(nb map[string][]string, n int) float64 {
	var k1, k2 float64
	for _, v := range nb {
		k := float64(len(v))
		k1 += k
		k2 += k * k
	}
	k1 /= float64(n)
	k2 /= float64(n)
	return k1 / (k2 - k1)
}

func pct(xs []float64, p float64) float64 {
	return xs[int(p*float64(len(xs)-1))]
}

func runEngine(name string, nsvc, n int, perMin float64, pods int, nu float64, crossMs int64) result {
	r := rand.New(rand.NewSource(42))
	svcs, nb := topology(r, nsvc, 4)
	alerts := storm(r, svcs, n, perMin, pods, nu)
	distinct := map[string]bool{}
	for _, a := range alerts {
		distinct[a.Fingerprint] = true
	}
	lat := make([]float64, n)
	var ms runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&ms)
	base := ms.HeapInuse // input slice etc.; engine memory is measured above this
	eng := engine.New(engine.Config{Window: 300_000, CrossWindow: crossMs, Lateness: 30_000, MaxFingerprints: 500, Neighbors: nb})
	peak := base
	total := 0
	incs := 0
	largest := 0
	start := time.Now()
	for i, a := range alerts {
		t0 := time.Now()
		for _, in := range eng.Ingest(a) {
			total += in.Total
			incs++
			largest = max(largest, in.Total)
		}
		lat[i] = float64(time.Since(t0).Nanoseconds()) / 1000
		if i%20_000 == 0 {
			runtime.ReadMemStats(&ms)
			if ms.HeapInuse > peak {
				peak = ms.HeapInuse
			}
		}
	}
	elapsed := time.Since(start)
	for _, in := range eng.Flush() {
		total += in.Total
		incs++
		largest = max(largest, in.Total)
	}
	sort.Float64s(lat)
	pc := percolationThreshold(nb, nsvc)
	// occupation probability of a neighbour within ±Wc: q = 1-exp(-nu*2Wc); solve q = pc
	nuCrit := -math.Log(1-pc) / (2 * float64(crossMs) / 3_600_000)
	return result{
		PercThresholdPc: pc, PredictedNuCrit: nuCrit,
		Scenario: name, Services: nsvc, Alerts: n, EventRatePerMin: perMin, DistinctFPs: len(distinct),
		ThroughputPerSec: float64(n) / elapsed.Seconds(),
		P50us:            pct(lat, 0.5), P99us: pct(lat, 0.99), P999us: pct(lat, 0.999), MaxUs: lat[n-1],
		PeakHeapMB: float64(peak-base) / (1 << 20), Incidents: incs, TotalConserved: total == n,
		NoisePerSvcHour: nu, CrossWindowSec: float64(crossMs) / 1000, LargestShare: float64(largest) / float64(n),
	}
}

func runHTTP(res *result, nsvc, n int, perMin float64, batch int) {
	r := rand.New(rand.NewSource(7))
	svcs, nb := topology(r, nsvc, 4)
	alerts := storm(r, svcs, n, perMin, 20, 3)
	eng := engine.New(engine.Config{Window: 300_000, Lateness: 30_000, MaxFingerprints: 500, Neighbors: nb})
	s := server.New(eng, func(engine.Incident) {}, nil)
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	var bodies [][]byte
	for i := 0; i < n; i += batch {
		type al struct {
			Status      string            `json:"status"`
			Labels      map[string]string `json:"labels"`
			Fingerprint string            `json:"fingerprint"`
		}
		var as []al
		for _, a := range alerts[i:min(i+batch, n)] {
			as = append(as, al{"firing", map[string]string{"alertname": a.Name, "service": a.Service}, a.Fingerprint})
		}
		b, _ := json.Marshal(map[string]interface{}{"version": "4", "alerts": as})
		bodies = append(bodies, b)
	}
	client := &http.Client{}
	start := time.Now()
	for _, b := range bodies {
		resp, err := client.Post(ts.URL+"/api/v1/alerts", "application/json", bytes.NewReader(b))
		if err != nil {
			panic(err)
		}
		resp.Body.Close()
	}
	res.HTTPAlertsPerSec = float64(n) / time.Since(start).Seconds()
	res.HTTPBatchSize = batch
}

func main() {
	out := flag.String("out", "", "write JSON results here")
	flag.Parse()
	var rs []result
	a := runEngine("storm_10k_per_min_200svc", 200, 1_000_000, 10_000, 20, 3, 60_000)
	runHTTP(&a, 200, 200_000, 10_000, 100)
	rs = append(rs, a)
	rs = append(rs, runEngine("storm_1M_per_min_1000svc", 1000, 2_000_000, 1_000_000, 50, 3, 60_000))
	// Percolation sweep: how much unrelated background noise until topology
	// grouping glues the fleet into one incident? (docs/DESIGN.md#percolation)
	for _, wc := range []int64{300_000, 60_000} {
		for _, nu := range []float64{0, 1, 3, 10, 30, 100} {
			rs = append(rs, runEngine(fmt.Sprintf("noise_sweep_nu%g_wc%ds", nu, wc/1000), 200, 300_000, 10_000, 20, nu, wc))
		}
	}
	meta := map[string]interface{}{
		"go":       runtime.Version(),
		"cpus":     runtime.NumCPU(),
		"goos":     runtime.GOOS,
		"goarch":   runtime.GOARCH,
		"date":     time.Now().UTC().Format(time.RFC3339),
		"window":   "5m",
		"lateness": "30s",
		"note":     "single goroutine engine; latency is wall time per Ingest call incl. evictions it triggers",
		"results":  rs,
	}
	b, _ := json.MarshalIndent(meta, "", "  ")
	fmt.Println(string(b))
	if *out != "" {
		if err := os.WriteFile(*out, b, 0o644); err != nil {
			panic(err)
		}
	}
}
