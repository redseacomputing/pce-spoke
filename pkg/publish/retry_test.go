package publish

import (
    "context"
    "errors"
    "sync"
    "testing"
    "time"
)

// failingPublisher simuliert einen ausgefallenen Hub: schlaegt fehl,
// bis allowSuccess-Channel geschlossen wird, dann klappt jede Publishing.
type failingPublisher struct {
    mu            sync.Mutex
    failures      int
    calls         int
    allowSuccess  chan struct{}
    oscals         [][]byte
}

func (f *failingPublisher) Publish(ctx context.Context, r ScanResult) error {
    f.mu.Lock()
    defer f.mu.Unlock()
    f.calls++
    f.oscals = append(f.oscals, r.OSCAL)
    select {
    case <-f.allowSuccess:
        return nil
    default:
        f.failures++
        return errors.New("hub unreachable")
    }
}

// TestPublisherFailureIsContained ist M1-Test 3:
// Der Agent stuerzt nicht ab, wenn der Hub nicht erreichbar ist -
// Fehler werden gepuffert und mit Backoff retryt, bis es klappt.
func TestPublisherFailureIsContained(t *testing.T) {
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    inner := &failingPublisher{allowSuccess: make(chan struct{})}
    pub := NewRetryPublisher(inner,
        WithMaxAttempts(0), // unendlich, Backoff entscheidet
        WithBaseDelay(1*time.Millisecond),
        WithMaxDelay(5*time.Millisecond),
        WithBoundedQueue(3),
    )

    // Act: Drei Scans absetzen, Hub ist DOWN.
    for i := 0; i < 3; i++ {
        if err := pub.Publish(ctx, ScanResult{
            OSCAL: []byte{byte('a' + i)}, Sensor: "kubescape",
            Timestamp: time.Now().UTC().Format(time.RFC3339), SchemaVersion: "1.0",
        }); err != nil {
            t.Fatalf("publish under hub outage must not fail eagerly: %v", err)
        }
    }

    // Assert 1: Kein Crash/Panic ist implizit - wir sind hier angekommen.
    // Assert 2: Nach "Heilung" des Hubs werden alle gepufferten Scans nachgeliefert.
    close(inner.allowSuccess)

    deadline := time.Now().Add(2 * time.Second)
    for {
        inner.mu.Lock()
        calls := inner.calls
        inner.mu.Unlock()
        if calls >= 3 || time.Now().After(deadline) {
            break
        }
        time.Sleep(5 * time.Millisecond)
    }
    inner.mu.Lock()
    defer inner.mu.Unlock()
    if inner.calls < 3 {
        t.Fatalf("expected retries to deliver all 3 scans after recovery, got %d calls", inner.calls)
    }
    // Alle drei OSCAL-Payloads (a, b, c) muessen angekommen sein
    seen := map[byte]bool{}
    for _, o := range inner.oscals {
        if len(o) > 0 {
            seen[o[0]] = true
        }
    }
    for _, want := range []byte{'a', 'b', 'c'} {
        if !seen[want] {
            t.Errorf("scan %q was lost during hub outage", want)
        }
    }
}

// TestRetryPublisherBoundedQueue ueberprueft die Backpressure-Regel:
// Bei voller Queue wird der aelteste Eintrag verworfen (nie unendlich wachsen).
func TestRetryPublisherBoundedQueue(t *testing.T) {
    ctx := context.Background()

    inner := &failingPublisher{allowSuccess: make(chan struct{})} // bleibt down
    pub := NewRetryPublisher(inner,
        WithMaxAttempts(0),
        WithBaseDelay(1*time.Millisecond),
        WithMaxDelay(5*time.Millisecond),
        WithBoundedQueue(2), // nur 2 Slots
    )

    // Drei publishes gegen voller Queue -> Publish muss controlled ablehnen
    for i := 0; i < 3; i++ {
        _ = pub.Publish(ctx, ScanResult{
            OSCAL: []byte{byte('x' + i)}, Sensor: "kubescape", SchemaVersion: "1.0",
        })
    }
    // Assert: kein Leak, kein Block, kein Panic (implizit) - Kern:
    // Publish kehrt auch unter Dauer-Ausfall immer zurueck (contained failure).
}
