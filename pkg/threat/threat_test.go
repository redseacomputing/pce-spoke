package threat

import (
    "context"
    "testing"
    "time"
)

func TestSnapshot_ActiveWindow(t *testing.T) {
    base := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)

    t.Run("fresh events within window are active", func(t *testing.T) {
        tr := NewTracker(Config{Clock: func() time.Time { return base }})
        tr.Ingest(Event{Rule: "Terminal shell in container", Container: "abc", Time: base.Add(-14 * time.Minute)})

        agg := tr.Snapshot()
        if agg.ActiveThreatCount != 1 {
            t.Fatalf("count = %d, want 1 (frisches Event)", agg.ActiveThreatCount)
        }
    })

    t.Run("stale events outside window are excluded", func(t *testing.T) {
        tr := NewTracker(Config{Clock: func() time.Time { return base }})
        tr.Ingest(Event{Rule: "Read sensitive file untrusted", Container: "def", Time: base.Add(-16 * time.Minute)})

        agg := tr.Snapshot()
        if agg.ActiveThreatCount != 0 {
            t.Fatalf("count = %d, want 0 (16min alt > 15min Fenster)", agg.ActiveThreatCount)
        }
    })

    t.Run("repeated lastSeen extends the window - silent container ages out", func(t *testing.T) {
        tr := NewTracker(Config{Clock: func() time.Time { return base }})
        // feuert von 12:00 bis 12:09 durchgehend
        for m := 0; m <= 9; m++ {
            tr.Ingest(Event{Rule: "Terminal shell in container", Container: "abc", Time: base.Add(time.Duration(m) * time.Minute)})
        }

        // Snapshot um 12:24: letztes Event 15min alt -> noch aktiv
        tr.cfg.Clock = func() time.Time { return base.Add(24 * time.Minute) }
        if tr.Snapshot().ActiveThreatCount != 1 {
            t.Fatalf("15min nach lastSeen muss noch aktiv sein")
        }

        // Snapshot um 12:25: 16min nach lastSeen -> abgelaufen
        tr.cfg.Clock = func() time.Time { return base.Add(25 * time.Minute) }
        agg := tr.Snapshot()
        if agg.ActiveThreatCount != 0 {
            t.Fatalf("16min nach lastSeen muss abgelaufen sein, got %d", agg.ActiveThreatCount)
        }
    })
}

func TestSnapshot_Dedup(t *testing.T) {
    base := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
    tr := NewTracker(Config{Clock: func() time.Time { return base }})

    // 40 Zeilen Shell-Ausgabe = 40 Events, EINE Shell-Sitzung
    for i := 0; i < 40; i++ {
        tr.Ingest(Event{Rule: "Terminal shell in container", Container: "abc", Time: base})
    }
    // gleiche Regel, anderer Container = separate Anomalie
    tr.Ingest(Event{Rule: "Terminal shell in container", Container: "xyz", Time: base})

    agg := tr.Snapshot()
    if agg.ActiveThreatCount != 2 {
        t.Fatalf("count = %d, want 2 (dedup nach Regel+Container)", agg.ActiveThreatCount)
    }
    if len(agg.Threats) != 2 {
        t.Fatalf("want 2 summaries, got %d", len(agg.Threats))
    }
    for _, s := range agg.Threats {
        if s.Rule == "Terminal shell in container" && s.Container == "abc" && s.Count != 40 {
            t.Fatalf("Count des abc-Aggregats = %d, want 40", s.Count)
        }
    }
}

func TestSnapshot_EmptyIsZeroNotNil(t *testing.T) {
    base := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
    tr := NewTracker(Config{Clock: func() time.Time { return base }})

    agg := tr.Snapshot()
    if agg.ActiveThreatCount != 0 {
        t.Fatalf("leerer Tracker muss 0 publisheden (verbundener Sensor, keine Anomalie)")
    }
    if agg.Threats == nil {
        t.Fatalf("Threats muss [] sein, nicht null (stabil JSON fuer den Hub)")
    }
    if agg.SchemaVersion != "1" {
        t.Fatalf("SchemaVersion = %q, want 1 (Evolutions-Stift zum Hub)", agg.SchemaVersion)
    }
}

// Run-Integration: Quelle still -> sauberes Ende; Ticker flushed mit Snapshot.
func TestRun_FlushesOnInterval(t *testing.T) {
    base := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
    tr := NewTracker(Config{
        FlushInterval: 50 * time.Millisecond,
        ActiveWindow: time.Hour,
        Clock:        func() time.Time { return base },
    })

    ch := make(chan Event, 4)
    go func() { ch <- Event{Rule: "R", Container: "c1", Time: base}; close(ch) }()

    flushes := 0
    err := Run(context.Background(), &chanSource{ch}, tr, func(Aggregate) error { flushes++; return nil })
    if err != nil {
        t.Fatalf("Run: %v", err)
    }
    if flushes < 1 {
        t.Fatalf("Run hat nicht geflusht (flushes=%d) - Quelle still beendet zu frueh", flushes)
    }
}

type chanSource struct{ ch chan Event }

func (s *chanSource) Events(ctx context.Context) (<-chan Event, error) { return s.ch, nil }
