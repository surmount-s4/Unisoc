package dedup

// ─── Alert Deduplication Module ───────────────────────────────────────────────
//
// Problem:  The same attack behaviour (e.g. repeated PowerShell encoded commands
//           from the same process) generates a new DB row on every event.
//           A SOC analyst would see thousands of near-identical rows instead of
//           one merged, escalating alert.
//
// Solution: Fingerprint each detection result with a SHA-256 hash of its key
//           fields.  If the same fingerprint is seen within the suppression
//           window (default 5 min) keep it in memory and only write the first
//           occurrence (plus a merged count) to the DB.
//
// Architecture:
//   Enrichment goroutines → Deduplicator.Feed() → Deduplicated events → DBWriter
//
// The Deduplicator is safe for concurrent use from multiple enrichment workers.

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log"
	"sync"
	"time"

	"uls-detection-server/internal/models"
)

// ─── Configuration ────────────────────────────────────────────────────────────

const (
	// SuppressWindow is how long a duplicate fingerprint is suppressed.
	// Identical detections within this window are merged, not re-inserted.
	SuppressWindow = 5 * time.Minute

	// GCInterval is how often the expired-fingerprint garbage collector runs.
	GCInterval = 10 * time.Minute

	// MaxCacheSize prevents unbounded memory growth, evicting oldest entries
	// when the cache exceeds this many distinct fingerprints.
	MaxCacheSize = 50_000
)

// ─── Entry ────────────────────────────────────────────────────────────────────

// entry tracks a single seen fingerprint.
type entry struct {
	FirstSeen  time.Time
	LastSeen   time.Time
	Count      int    // number of duplicate events suppressed so far
	Host       string // for logging
}

// ─── Deduplicator ─────────────────────────────────────────────────────────────

// Deduplicator filters duplicate detections within a sliding time window.
// Unique events pass through; duplicates are merged and only the FIRST event
// of each window (with an updated DuplicateCount) reaches the DB writer.
type Deduplicator struct {
	mu       sync.RWMutex
	cache    map[string]*entry  // fingerprint → entry
	passThru chan models.SecurityEvent
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup

	// Stats
	totalSeen       int64
	totalSuppressed int64
}

// New creates a Deduplicator that writes unique events to the returned channel.
// The caller must drain that channel and pass events to the DB writer.
func New(ctx context.Context) (*Deduplicator, <-chan models.SecurityEvent) {
	ctx2, cancel := context.WithCancel(ctx)
	out := make(chan models.SecurityEvent, 2048)

	d := &Deduplicator{
		cache:    make(map[string]*entry, 1024),
		passThru: out,
		ctx:      ctx2,
		cancel:   cancel,
	}

	d.wg.Add(1)
	go d.gcLoop()

	log.Printf("[Dedup] Started (suppress window=%v, max cache=%d)", SuppressWindow, MaxCacheSize)
	return d, out
}

// Feed evaluates a detected event.  If it is the first occurrence of its
// fingerprint within SuppressWindow it is forwarded downstream.
// Subsequent duplicates increment the counter only; when the window expires
// and the next occurrence arrives it passes through again with the aggregate
// count so the DB writer can upsert.
//
// Events with Severity=="INFO" and no detected technique bypass dedup entirely
// (they are too low-value to cache) and are simply forwarded.
func (d *Deduplicator) Feed(event models.SecurityEvent) {
	// Always forward non-detected INFO events immediately
	if event.Severity == "INFO" && event.MitreTechnique == "" {
		select {
		case d.passThru <- event:
		default:
		}
		return
	}

	fp := fingerprint(event)

	d.mu.Lock()
	defer d.mu.Unlock()

	d.totalSeen++

	if e, exists := d.cache[fp]; exists {
		now := time.Now()
		if now.Sub(e.FirstSeen) < SuppressWindow {
			// Within window → suppress, just update stats
			e.Count++
			e.LastSeen = now
			d.totalSuppressed++
			return
		}
		// Window expired → treat as fresh, carry forward merged count
		event.DuplicateCount = e.Count + 1
		e.FirstSeen = now
		e.LastSeen = now
		e.Count = 0
	} else {
		// Brand-new fingerprint
		if len(d.cache) >= MaxCacheSize {
			d.evictOldest()
		}
		d.cache[fp] = &entry{
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
			Count:     0,
			Host:      event.AgentHost,
		}
		event.DuplicateCount = 0
	}

	select {
	case d.passThru <- event:
	default:
		log.Println("[Dedup] Pass-through channel full, dropping event")
	}
}

// Stop shuts down the background goroutine and closes the output channel.
func (d *Deduplicator) Stop() {
	d.cancel()
	d.wg.Wait()
	close(d.passThru)
	log.Printf("[Dedup] Stopped. Seen: %d  Suppressed: %d  (%.1f%% noise reduction)",
		d.totalSeen, d.totalSuppressed,
		percentage(d.totalSuppressed, d.totalSeen))
}

// Stats returns current cache size and suppression totals (for Grafana metrics).
func (d *Deduplicator) Stats() (cacheSize int, seen, suppressed int64) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.cache), d.totalSeen, d.totalSuppressed
}

// ─── Fingerprinting ───────────────────────────────────────────────────────────

// fingerprint produces a stable identifier for an alert that represents the
// same "threat behaviour".  It intentionally excludes timestamps and
// process IDs so that the same malicious technique triggered repeatedly by
// the same binary on the same host maps to a single fingerprint.
//
//   Key ingredients:
//     host          – so different machines are separate alerts
//     event_id      – Sysmon/Security/System event type
//     mitre         – the specific ATT&CK technique
//     detection_mod – Execution / Persistence / CredentialAccess etc.
//     image         – the offending binary path (Level-2 Sysmon field)
//     dest_ip+port  – for network detections, the C2 endpoint
//
// Optional: command_line is NOT included because it can vary per invocation
// for the same conceptual attack (e.g. obfuscated variants of the same download
// cradle).  Include it only for exact-match dedup by changing hashFields below.
func fingerprint(e models.SecurityEvent) string {
	hashFields := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s",
		e.AgentHost,
		e.EventID0,
		e.MitreTechnique,
		e.DetectionModule,
		e.Image2,
		e.DestinationIp2,
		e.DestinationPort2,
	)
	sum := sha256.Sum256([]byte(hashFields))
	return fmt.Sprintf("%x", sum)
}

// ─── Garbage Collector ────────────────────────────────────────────────────────

func (d *Deduplicator) gcLoop() {
	defer d.wg.Done()
	ticker := time.NewTicker(GCInterval)
	defer ticker.Stop()

	for {
		select {
		case <-d.ctx.Done():
			return
		case <-ticker.C:
			d.gc()
		}
	}
}

// gc removes entries whose suppression window has fully elapsed.
func (d *Deduplicator) gc() {
	d.mu.Lock()
	defer d.mu.Unlock()

	cutoff := time.Now().Add(-SuppressWindow)
	removed := 0
	for fp, e := range d.cache {
		if e.LastSeen.Before(cutoff) {
			delete(d.cache, fp)
			removed++
		}
	}
	if removed > 0 {
		log.Printf("[Dedup] GC: removed %d expired fingerprints (cache size: %d)", removed, len(d.cache))
	}
}

// evictOldest removes the single oldest cache entry when the cache is full.
// In practice MaxCacheSize is large enough that this is rarely triggered.
func (d *Deduplicator) evictOldest() {
	var oldestFP string
	var oldestTime time.Time

	for fp, e := range d.cache {
		if oldestFP == "" || e.FirstSeen.Before(oldestTime) {
			oldestFP = fp
			oldestTime = e.FirstSeen
		}
	}
	if oldestFP != "" {
		delete(d.cache, oldestFP)
	}
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func percentage(part, total int64) float64 {
	if total == 0 {
		return 0
	}
	return float64(part) / float64(total) * 100
}
