package engine

import (
	"fmt"
	"math/rand"
	"reflect"
	"sort"
	"strings"
	"testing"
	"testing/quick"
)

// ---- random scenario generator for property tests -------------------------

type scenario struct {
	Window, Cross, Lateness int64
	Neighbors               map[string][]string
	Alerts                  []Alert // in event-time order
	Seed                    int64
}

func (scenario) Generate(r *rand.Rand, size int) reflect.Value {
	nsvc := 2 + r.Intn(8)
	svcs := make([]string, nsvc)
	for i := range svcs {
		svcs[i] = fmt.Sprintf("s%d", i)
	}
	nb := map[string][]string{}
	for i := 0; i < nsvc; i++ {
		for j := i + 1; j < nsvc; j++ {
			if r.Float64() < 0.3 {
				nb[svcs[i]] = append(nb[svcs[i]], svcs[j])
				nb[svcs[j]] = append(nb[svcs[j]], svcs[i])
			}
		}
	}
	w := int64(1 + r.Intn(50))
	sc := scenario{Window: w, Cross: 1 + r.Int63n(w), Lateness: int64(r.Intn(40)), Neighbors: nb, Seed: r.Int63()}
	n := 1 + r.Intn(10+size*3)
	t := int64(0)
	for i := 0; i < n; i++ {
		t += int64(r.Intn(30))
		s := svcs[r.Intn(nsvc)]
		name := []string{"HighErrorRate", "HighLatency", "TargetDown"}[r.Intn(3)]
		sc.Alerts = append(sc.Alerts, Alert{Fingerprint: name + "|" + s, Name: name, Service: s, TS: t})
	}
	return reflect.ValueOf(sc)
}

// arrivalOrder returns a permutation whose out-of-orderness is bounded by Lateness:
// sort by ts + U[0, Lateness].
func arrivalOrder(sc scenario, seed int64) []Alert {
	r := rand.New(rand.NewSource(seed))
	type k struct {
		key float64
		a   Alert
	}
	ks := make([]k, len(sc.Alerts))
	for i, a := range sc.Alerts {
		ks[i] = k{float64(a.TS) + r.Float64()*float64(sc.Lateness), a}
	}
	sort.SliceStable(ks, func(i, j int) bool { return ks[i].key < ks[j].key })
	out := make([]Alert, len(ks))
	for i := range ks {
		out[i] = ks[i].a
	}
	return out
}

func run(sc scenario, order []Alert, maxFP int) []Incident {
	e := New(Config{Window: sc.Window, CrossWindow: sc.Cross, Lateness: sc.Lateness, Neighbors: sc.Neighbors, MaxFingerprints: maxFP})
	var out []Incident
	for _, a := range order {
		out = append(out, e.Ingest(a)...)
	}
	return append(out, e.Flush()...)
}

// canonical form of a set of incidents (independent of emission order)
func canon(incs []Incident) []string {
	var out []string
	for _, in := range incs {
		var fps []string
		for _, a := range in.Alerts {
			fps = append(fps, fmt.Sprintf("%s=%d", a.Fingerprint, a.Count))
		}
		out = append(out, fmt.Sprintf("%v|%d|%s|%d|%d", in.Services, in.Total, strings.Join(fps, ","), in.First, in.Last))
	}
	sort.Strings(out)
	return out
}

// reference: O(n^2) connected components straight from the specification.
func reference(sc scenario) []Incident {
	n := len(sc.Alerts)
	parent := make([]int, n)
	for i := range parent {
		parent[i] = i
	}
	var f func(int) int
	f = func(x int) int {
		for parent[x] != x {
			x = parent[x]
		}
		return x
	}
	linked := func(a, b Alert) bool {
		d := a.TS - b.TS
		if d < 0 {
			d = -d
		}
		if a.Service == b.Service {
			return d <= sc.Window
		}
		for _, x := range sc.Neighbors[a.Service] {
			if x == b.Service {
				return d <= sc.Cross
			}
		}
		return false
	}
	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			if linked(sc.Alerts[i], sc.Alerts[j]) {
				parent[f(i)] = f(j)
			}
		}
	}
	groups := map[int][]Alert{}
	for i, a := range sc.Alerts {
		groups[f(i)] = append(groups[f(i)], a)
	}
	var out []Incident
	for _, g := range groups {
		in := Incident{Total: len(g), First: g[0].TS, Last: g[0].TS}
		svc := map[string]bool{}
		fp := map[string]*FPAgg{}
		for _, a := range g {
			svc[a.Service] = true
			in.First = min64(in.First, a.TS)
			in.Last = max64(in.Last, a.TS)
			if x, ok := fp[a.Fingerprint]; ok {
				x.Count++
			} else {
				fp[a.Fingerprint] = &FPAgg{Fingerprint: a.Fingerprint, Count: 1}
			}
		}
		for s := range svc {
			in.Services = append(in.Services, s)
		}
		sort.Strings(in.Services)
		for _, x := range fp {
			in.Alerts = append(in.Alerts, *x)
		}
		sort.Slice(in.Alerts, func(i, j int) bool { return in.Alerts[i].Fingerprint < in.Alerts[j].Fingerprint })
		out = append(out, in)
	}
	return out
}

var qc = &quick.Config{MaxCount: 2000}

// Property 1: the streaming engine equals the brute-force specification.
func TestMatchesReference(t *testing.T) {
	f := func(sc scenario) bool {
		got := canon(run(sc, arrivalOrder(sc, sc.Seed), 0))
		want := canon(reference(sc))
		if !reflect.DeepEqual(got, want) {
			t.Logf("W=%d Wc=%d L=%d\n got=%v\nwant=%v", sc.Window, sc.Cross, sc.Lateness, got, want)
			return false
		}
		return true
	}
	if err := quick.Check(f, qc); err != nil {
		t.Fatal(err)
	}
}

// Property 2: grouping is independent of arrival order (within Lateness).
func TestOrderIndependent(t *testing.T) {
	f := func(sc scenario) bool {
		a := canon(run(sc, arrivalOrder(sc, sc.Seed), 0))
		b := canon(run(sc, arrivalOrder(sc, sc.Seed+1), 0))
		return reflect.DeepEqual(a, b)
	}
	if err := quick.Check(f, qc); err != nil {
		t.Fatal(err)
	}
}

// Property 3: conservation. No alert is lost or double counted, even when
// storm suppression drops fingerprints from the incident body, and even with
// arbitrarily late arrivals (fully shuffled input).
func TestConservation(t *testing.T) {
	f := func(sc scenario, maxFP uint8, shuffle bool) bool {
		order := arrivalOrder(sc, sc.Seed)
		if shuffle {
			r := rand.New(rand.NewSource(sc.Seed))
			r.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })
		}
		incs := run(sc, order, 1+int(maxFP%4))
		total := 0
		for _, in := range incs {
			sum := in.Suppressed
			for _, a := range in.Alerts {
				sum += a.Count
			}
			if sum != in.Total {
				return false
			}
			total += in.Total
		}
		return total == len(sc.Alerts)
	}
	if err := quick.Check(f, qc); err != nil {
		t.Fatal(err)
	}
}

func TestStormCollapsesToOneSegment(t *testing.T) {
	e := New(Config{Window: 60_000, Neighbors: map[string][]string{}})
	for i := 0; i < 100_000; i++ {
		e.Ingest(Alert{Fingerprint: "x", Service: "frontend", TS: int64(i * 10)})
	}
	if got := e.Stats().LiveSegments; got != 1 {
		t.Fatalf("live segments = %d, want 1", got)
	}
	incs := e.Flush()
	if len(incs) != 1 || incs[0].Total != 100_000 || len(incs[0].Alerts) != 1 {
		t.Fatalf("unexpected %+v", incs)
	}
}

func TestTopologyMerge(t *testing.T) {
	nb := map[string][]string{"frontend": {"cart"}, "cart": {"frontend", "redis"}, "redis": {"cart"}}
	e := New(Config{Window: 100, Neighbors: nb})
	e.Ingest(Alert{Fingerprint: "a", Service: "frontend", TS: 0})
	e.Ingest(Alert{Fingerprint: "b", Service: "redis", TS: 50}) // not adjacent to frontend
	e.Ingest(Alert{Fingerprint: "c", Service: "cart", TS: 60})  // bridges both
	incs := e.Flush()
	if len(incs) != 1 || !reflect.DeepEqual(incs[0].Services, []string{"cart", "frontend", "redis"}) {
		t.Fatalf("got %+v", incs)
	}
}
