package publish

import (
    "context"
    "fmt"
    "log"
    "sync"
    "time"
)

type retryConfig struct {
    maxAttempts  int           // 0 = unbegrenzt (Requeue-Vertrag wie Hub-GT4)
    baseDelay    time.Duration
    maxDelay     time.Duration
    queueSize    int
}

type RetryOption func(*retryConfig)

func WithMaxAttempts(n int) RetryOption       { return func(c *retryConfig) { c.maxAttempts = n } }
func WithBaseDelay(d time.Duration) RetryOption { return func(c *retryConfig) { c.baseDelay = d } }
func WithMaxDelay(d time.Duration) RetryOption  { return func(c *retryConfig) { c.maxDelay = d } }
func WithBoundedQueue(n int) RetryOption      { return func(c *retryConfig) { c.queueSize = n } }

// RetryPublisher ist ein Dekorator um jedes Publisher: bei Transientfehlern
// werden Ergebnisse in einer bounded Queue gepuffert und mit exponentiellem
// Backoff retryt. Er crasht nie, blockiert den Caller nie dauerhaft und
// verwirft bei voller Queue das AELTESTE Ergebnis (bounded memory).
type RetryPublisher struct {
    inner Publisher
    cfg   retryConfig

    mu    sync.Mutex
    queue []ScanResult
}

func NewRetryPublisher(inner Publisher, opts ...RetryOption) *RetryPublisher {
    cfg := retryConfig{
        maxAttempts: 0,
        baseDelay:   1 * time.Second,
        maxDelay:    1 * time.Minute,
        queueSize:   10,
    }
    for _, o := range opts {
        o(&cfg)
    }
    rp := &RetryPublisher{inner: inner, cfg: cfg}
    go rp.drainLoop()
    return rp
}

// Publish stellt das Ergebnis in die Queue und kehrt sofort zurueck
// (contained failure: der Sensorlauf wird nie blockiert).
func (rp *RetryPublisher) Publish(ctx context.Context, result ScanResult) error {
    rp.mu.Lock()
    defer rp.mu.Unlock()
    if len(rp.queue) >= rp.cfg.queueSize {
        dropped := rp.queue[0]
        rp.queue = rp.queue[1:]
        log.Printf("publish queue full, dropping oldest scan (sensor=%s ts=%s)",
            dropped.Sensor, dropped.Timestamp)
    }
    rp.queue = append(rp.queue, result)
    return nil
}

// drainLoop arbeitet die Queue mit Backoff ab. Läuft bis Prozessende.
func (rp *RetryPublisher) drainLoop() {
    delay := rp.cfg.baseDelay
    for {
        rp.mu.Lock()
        var next *ScanResult
        if len(rp.queue) > 0 {
            n := rp.queue[0]
            next = &n
        }
        rp.mu.Unlock()
        if next == nil {
            time.Sleep(rp.cfg.baseDelay) // idle
            continue
        }

        err := rp.inner.Publish(context.Background(), *next)
        if err == nil {
            delay = rp.cfg.baseDelay // Backoff zuruecksetzen nach Erfolg
            rp.mu.Lock()
            rp.queue = rp.queue[1:]
            rp.mu.Unlock()
            continue
        }

        log.Printf("publish failed (will retry): %v", err)
        if rp.cfg.maxAttempts > 0 {
            // nicht weiter zaehlen im M1-Default (0 = unbegrenzt); bei
            // maxAttempts>0 koennte hier Drop-after-N folgen.
        }
        time.Sleep(delay)
        delay *= 2
        if delay > rp.cfg.maxDelay {
            delay = rp.cfg.maxDelay
        }
    }
}

var _ = fmt.Sprintf // Platzhalter; entfernen, falls der Linter meckert
