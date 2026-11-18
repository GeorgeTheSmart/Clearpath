package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/GeorgeTheSmart/clearpath/correlator/engine"
)

func TestWebhookToIncident(t *testing.T) {
	clock := int64(0)
	var got []engine.Incident
	eng := engine.New(engine.Config{Window: 1000, Neighbors: map[string][]string{"frontend": {"cartservice"}, "cartservice": {"frontend"}}})
	s := New(eng, func(i engine.Incident) { got = append(got, i) }, func() int64 { return clock })
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	post := func(body string) int {
		resp, err := http.Post(ts.URL+"/api/v1/alerts", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	a := `{"version":"4","alerts":[{"status":"firing","fingerprint":"f1","labels":{"alertname":"HighErrorRate","service":"cartservice","severity":"critical"}},` +
		`{"status":"firing","fingerprint":"f2","labels":{"alertname":"HighLatencyP99","service":"frontend"}},` +
		`{"status":"resolved","fingerprint":"f3","labels":{"alertname":"X","service":"frontend"}}]}`
	if c := post(a); c != http.StatusAccepted {
		t.Fatalf("status %d", c)
	}
	clock = 500
	post(a) // re-send: deduplicated into counts
	if c := post("{not json"); c != http.StatusBadRequest {
		t.Fatalf("bad json status %d", c)
	}
	clock = 10_000
	s.Tick()
	if len(got) != 1 || got[0].Total != 4 || len(got[0].Alerts) != 2 {
		t.Fatalf("got %+v", got)
	}
	resp, err := http.Get(ts.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(b), "correlator_alerts_ingested_total 4") {
		t.Fatalf("metrics: %s", b)
	}
}
