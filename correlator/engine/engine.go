// Package engine groups a stream of alerts into incidents.
//
// Grouping rule (the specification the tests check against a brute-force
// reference): two alert occurrences a, b are linked when
//
//	service(a) == service(b)            and |ts(a) - ts(b)| <= Window, or
//	the services are adjacent in the    and |ts(a) - ts(b)| <= CrossWindow
//	dependency graph
//
// CrossWindow <= Window. A tighter cross-service window keeps unrelated
// background alerts from percolating across a connected topology into one
// giant incident (docs/DESIGN.md#percolation).
//
// An incident is a connected component of that graph. This definition does not
// mention arrival order, so the result is order-independent as long as arrivals
// are at most Lateness out of order.
//
// Data structure: per service we keep "segments", maximal runs of that service's
// occurrences whose consecutive gaps are <= CrossWindow. Inside a segment every
// occurrence is linked to the next one, so the whole segment is in one
// component, and because gaps <= CrossWindow <= Window, "is some occurrence
// within X of t" (X = Window or CrossWindow) reduces exactly to the interval test
// t ∈ [tmin-X, tmax+X]. A storm of N alerts on one service is one
// segment, so memory is O(live segments), not O(alerts). Components are a
// union-find over incident records. Closed segments are evicted from a min-heap
// keyed by tmax+Window+Lateness; an incident is emitted when its last segment is
// evicted, i.e. when no future in-order alert could still join it.
//
// See docs/DESIGN.md#correlator for the complexity argument.
package engine

import (
	"container/heap"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"sort"
)

// Alert is one received occurrence (Alertmanager re-sends firing alerts).
type Alert struct {
	Fingerprint string `json:"fingerprint"`
	Name        string `json:"name"`
	Service     string `json:"service"`
	Severity    string `json:"severity"`
	TS          int64  `json:"ts"` // milliseconds
}

// FPAgg is the deduplicated view of one fingerprint inside an incident.
type FPAgg struct {
	Fingerprint string `json:"fingerprint"`
	Name        string `json:"name"`
	Service     string `json:"service"`
	Severity    string `json:"severity"`
	Count       int    `json:"count"`
	First       int64  `json:"first"`
	Last        int64  `json:"last"`
}

// Incident is emitted when a component can no longer grow.
type Incident struct {
	ID         string   `json:"id"`
	Services   []string `json:"services"`
	Alerts     []FPAgg  `json:"alerts"`
	Suppressed int      `json:"suppressed"` // occurrences of fingerprints beyond MaxFingerprints
	Total      int      `json:"total"`      // all occurrences, including duplicates and suppressed
	First      int64    `json:"first"`
	Last       int64    `json:"last"`
	Late       bool     `json:"late"` // contains an alert that arrived beyond Lateness
}

// Config controls grouping.
type Config struct {
	Window          int64               // ms, same-service link window
	CrossWindow     int64               // ms, neighbour link window; 0 means Window
	Lateness        int64               // ms of tolerated out-of-order arrival
	MaxFingerprints int                 // storm suppression: distinct fingerprints kept per incident
	Neighbors       map[string][]string // undirected service adjacency
}

type comp struct {
	parent     *comp
	services   map[string]struct{}
	fps        map[string]*FPAgg
	suppressed int
	total      int
	first      int64
	last       int64
	live       int // live segments pointing into this component
	late       bool
}

type segment struct {
	svc        string
	tmin, tmax int64
	c          *comp
	alive      bool
	scheduled  bool // has exactly one entry in the heap
}

type heapItem struct {
	deadline int64
	seg      *segment
}

type segHeap []heapItem

func (h segHeap) Len() int            { return len(h) }
func (h segHeap) Less(i, j int) bool  { return h[i].deadline < h[j].deadline }
func (h segHeap) Swap(i, j int)       { h[i], h[j] = h[j], h[i] }
func (h *segHeap) Push(x interface{}) { *h = append(*h, x.(heapItem)) }
func (h *segHeap) Pop() interface{} {
	old := *h
	it := old[len(old)-1]
	*h = old[:len(old)-1]
	return it
}

// Stats are cumulative counters, exposed on /metrics by the server.
type Stats struct {
	Ingested       int64
	Late           int64
	Emitted        int64
	LiveSegments   int64
	OpenIncidents  int64
	SuppressedOccs int64
}

// Engine is not safe for concurrent use; the server serialises access.
type Engine struct {
	cfg       Config
	segs      map[string][]*segment
	h         segHeap
	watermark int64
	started   bool
	open      int64
	stats     Stats
}

// New returns an engine. Window must be > 0.
func New(cfg Config) *Engine {
	if cfg.Window <= 0 {
		panic("engine: Window must be positive")
	}
	if cfg.CrossWindow <= 0 || cfg.CrossWindow > cfg.Window {
		cfg.CrossWindow = cfg.Window
	}
	if cfg.MaxFingerprints <= 0 {
		cfg.MaxFingerprints = 1 << 30
	}
	return &Engine{cfg: cfg, segs: map[string][]*segment{}}
}

func find(c *comp) *comp {
	for c.parent != c {
		c.parent = c.parent.parent // path halving
		c = c.parent
	}
	return c
}

func (e *Engine) union(a, b *comp) *comp {
	ra, rb := find(a), find(b)
	if ra == rb {
		return ra
	}
	// union by size (number of fingerprints), small-into-large map merging
	if len(ra.fps)+len(ra.services) < len(rb.fps)+len(rb.services) {
		ra, rb = rb, ra
	}
	rb.parent = ra
	for s := range rb.services {
		ra.services[s] = struct{}{}
	}
	for fp, ag := range rb.fps {
		if cur, ok := ra.fps[fp]; ok {
			cur.Count += ag.Count
			cur.First = min64(cur.First, ag.First)
			cur.Last = max64(cur.Last, ag.Last)
		} else if len(ra.fps) < e.cfg.MaxFingerprints {
			ra.fps[fp] = ag
		} else {
			ra.suppressed += ag.Count
			e.stats.SuppressedOccs += int64(ag.Count)
		}
	}
	ra.suppressed += rb.suppressed
	ra.total += rb.total
	ra.first = min64(ra.first, rb.first)
	ra.last = max64(ra.last, rb.last)
	ra.live += rb.live
	ra.late = ra.late || rb.late
	rb.services, rb.fps = nil, nil
	e.open--
	return ra
}

// Ingest adds one occurrence and returns any incidents closed by the watermark advance.
func (e *Engine) Ingest(a Alert) []Incident {
	e.stats.Ingested++
	late := e.started && a.TS < e.watermark-e.cfg.Lateness
	if late {
		e.stats.Late++
	}
	W, Wc := e.cfg.Window, e.cfg.CrossWindow

	c := &comp{
		services: map[string]struct{}{a.Service: {}},
		fps: map[string]*FPAgg{a.Fingerprint: {
			Fingerprint: a.Fingerprint, Name: a.Name, Service: a.Service, Severity: a.Severity,
			Count: 1, First: a.TS, Last: a.TS,
		}},
		total: 1, first: a.TS, last: a.TS, late: late,
	}
	c.parent = c
	e.open++
	root := c

	// 1. link to neighbour services' segments
	for _, n := range e.cfg.Neighbors[a.Service] {
		if n == a.Service {
			continue
		}
		for _, s := range e.segs[n] {
			if a.TS >= s.tmin-Wc && a.TS <= s.tmax+Wc {
				root = e.union(root, s.c)
			}
		}
	}
	// 2. link to own-service segments within W; merge runs within Wc
	own := e.segs[a.Service]
	var keep *segment
	kept := own[:0]
	for _, s := range own {
		if a.TS >= s.tmin-W && a.TS <= s.tmax+W {
			root = e.union(root, s.c)
		}
		if a.TS >= s.tmin-Wc && a.TS <= s.tmax+Wc {
			if keep == nil {
				keep = s
				kept = append(kept, s)
			} else {
				keep.tmin = min64(keep.tmin, s.tmin)
				keep.tmax = max64(keep.tmax, s.tmax)
				s.alive = false
				find(root).live--
				e.stats.LiveSegments--
			}
			continue
		}
		kept = append(kept, s)
	}
	root = find(root)
	if keep == nil {
		keep = &segment{svc: a.Service, tmin: a.TS, tmax: a.TS, c: root, alive: true}
		kept = append(kept, keep)
		root.live++
		e.stats.LiveSegments++
	} else {
		keep.tmin = min64(keep.tmin, a.TS)
		keep.tmax = max64(keep.tmax, a.TS)
		keep.c = root
	}
	e.segs[a.Service] = kept
	if !keep.scheduled {
		// One heap entry per live segment. When a segment grows its deadline
		// only increases, so the entry is rescheduled lazily when popped.
		heap.Push(&e.h, heapItem{deadline: keep.tmax + W + e.cfg.Lateness, seg: keep})
		keep.scheduled = true
	}

	if !e.started || a.TS > e.watermark {
		e.watermark = a.TS
		e.started = true
	}
	return e.evict(false)
}

// Advance moves the watermark (e.g. from a wall-clock ticker) and closes incidents.
func (e *Engine) Advance(now int64) []Incident {
	if now > e.watermark {
		e.watermark = now
		e.started = true
	}
	return e.evict(false)
}

// Flush closes everything (end of a replay).
func (e *Engine) Flush() []Incident { return e.evict(true) }

func (e *Engine) evict(all bool) []Incident {
	var out []Incident
	for e.h.Len() > 0 {
		it := e.h[0]
		if !all && it.deadline >= e.watermark {
			break
		}
		heap.Pop(&e.h)
		s := it.seg
		if !s.alive {
			continue // merged into another segment
		}
		if cur := s.tmax + e.cfg.Window + e.cfg.Lateness; it.deadline < cur {
			heap.Push(&e.h, heapItem{deadline: cur, seg: s}) // segment grew: reschedule
			continue
		}
		s.alive = false
		e.stats.LiveSegments--
		lst := e.segs[s.svc]
		for i, x := range lst {
			if x == s {
				lst[i] = lst[len(lst)-1]
				lst = lst[:len(lst)-1]
				break
			}
		}
		if len(lst) == 0 {
			delete(e.segs, s.svc)
		} else {
			e.segs[s.svc] = lst
		}
		r := find(s.c)
		r.live--
		if r.live == 0 {
			out = append(out, e.emit(r))
		}
	}
	return out
}

func (e *Engine) emit(r *comp) Incident {
	inc := Incident{Suppressed: r.suppressed, Total: r.total, First: r.first, Last: r.last, Late: r.late}
	for s := range r.services {
		inc.Services = append(inc.Services, s)
	}
	sort.Strings(inc.Services)
	for _, ag := range r.fps {
		inc.Alerts = append(inc.Alerts, *ag)
	}
	sort.Slice(inc.Alerts, func(i, j int) bool { return inc.Alerts[i].Fingerprint < inc.Alerts[j].Fingerprint })
	// Content-derived ID: identical incidents get identical IDs in any arrival order.
	h := sha1.New()
	fmt.Fprintf(h, "%d|%v", inc.First, inc.Services)
	inc.ID = "inc-" + hex.EncodeToString(h.Sum(nil))[:12]
	e.stats.Emitted++
	e.open--
	return inc
}

// Stats returns a copy of the counters.
func (e *Engine) Stats() Stats {
	s := e.stats
	s.OpenIncidents = e.open
	return s
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
