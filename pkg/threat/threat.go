// Package threat aggregiert Falco-Runtime-Events zu dem Hub-Vertrag:
// activeThreatCount = Anzahl der (deduplizierten) Anomalien, deren lastSeen
// im ActiveWindow liegt. "Aktiv" ist eine reine Zeitaussage des Spokes.
package threat

import (
	"time"
	"context"
)

// Event ist ein Falco-Event, normalisiert aus dem gRPC-Output.
// pkg/threat kennt kein Falco-Rohformat - der Adapter (grpc.go) reduziert.
type Event struct {
    Rule      string    // z. B. "Terminal shell in container"
    Container string    // Container-ID (oder Name) des Ziels
    Time      time.Time // Zeitstempel des Events (Falco liefert ihn mit)
    Output    string    // menschenlesbare Beschreibung (nur fuer Debug)
}

// Source abstrahiert den Falco-Event-Stream. Die Produktion impl. ist
// der gRPC-Subscribe; Tests implementieren ein Channel-Stub.
type Source interface {
    // Events liefert einen Kanal, der bei ctx-Abbruch geschlossen wird.
    Events(ctx context.Context) (<-chan Event, error)
}

// Config ist der Vertrag aus der GT3-Vertragsrunde:
// ActiveWindow (15min), FlushInterval (1min), Dedup nach Regel+Container.
type Config struct {
    ActiveWindow time.Duration // ein Event ist aktiv, solange now-Time <= ActiveWindow
    FlushInterval time.Duration // Publish-Kadenz (<= ActiveWindow!)
    // Clock ist injizierbar fuer Vertragstests (Fenster-Ablauf ohne Sleep).
    Clock func() time.Time
}

func (c Config) withDefaults() Config {
    if c.ActiveWindow == 0 {
        c.ActiveWindow = 15 * time.Minute
    }
    if c.FlushInterval == 0 {
        c.FlushInterval = time.Minute
    }
    if c.FlushInterval > c.ActiveWindow {
        c.FlushInterval = c.ActiveWindow // Kadenz darf das Fenster nie ueberschreiten
    }
    if c.Clock == nil {
        c.Clock = time.Now
    }
    return c
}

// Summary ist EIN dedupliziertes Aggregat (Regel+Container).
type Summary struct {
    Rule      string    `json:"rule"`
    Container string    `json:"container"`
    Count     int32     `json:"count"`
    FirstSeen time.Time `json:"firstSeen"`
    LastSeen  time.Time `json:"lastSeen"`
}

// Aggregate ist das fertige Publish-Format - identisch mit dem,
// was der Hub-Test (GT3, threatAggregate) konsumiert. SchemaVersion
// ist der evolutionaere Stift zwischen Spoke und Hub.
type Aggregate struct {
    SchemaVersion      string    `json:"schemaVersion"`
    ActiveThreatCount  int32     `json:"activeThreatCount"`
    Threats            []Summary `json:"threats"`
    GeneratedAt        time.Time `json:"generatedAt"`
}

// Tracker haelt die Aggregationsstruktur in-memory. Nicht nebenlaeufig:
// Der Runner (Run) serialisiert Ingest und Snapshot - kein Lock noetig.
type Tracker struct {
    cfg    Config
    active map[string]*Summary // key: rule + "\x00" + container
}

func NewTracker(cfg Config) *Tracker {
    return &Tracker{cfg: cfg.withDefaults(), active: map[string]*Summary{}}
}

// Ingest verarbeitet ein Event: Regel+Container-Anlage bzw. Update
// von Count und LastSeen (der Zeitstempel laengt das Fenster an - ein
// dauerhaft feuender Container bleibt "aktiv", bis er still wird).
// Dedup ist vertraglich fix: ein Aggregat = Regel + Container.
func (t *Tracker) Ingest(e Event) {
    key := e.Rule + "\x00" + e.Container
    s, ok := t.active[key]
    if !ok {
        s = &Summary{Rule: e.Rule, Container: e.Container, FirstSeen: e.Time}
        t.active[key] = s
    }
    s.Count++
    s.LastSeen = e.Time
}

// Snapshot berechnet das Publish-Format zum Zeitpunkt now und raeumt
// abgelaufene Aggregate weg (Keep-It-Tidy: map wächst sonst ewig).
func (t *Tracker) Snapshot() Aggregate {
    now := t.cfg.Clock()
    agg := Aggregate{SchemaVersion: "1", GeneratedAt: now}

    for key, s := range t.active {
        if now.Sub(s.LastSeen) > t.cfg.ActiveWindow {
            delete(t.active, key) // abgelaufen: raus aus der Struktur
            continue
        }
        agg.Threats = append(agg.Threats, *s)
        agg.ActiveThreatCount++
    }
    if agg.Threats == nil {
        agg.Threats = []Summary{} // stabiles JSON: [] statt null
    }
    return agg
}

// Run verdrahtet Source + Tracker: Events ingestieren (bis ctx zu),
// FlushInterval-getaktet das Aggregat an flush() geben.
// Der Hub-Vertrag: 0 wird explizit published, solange der Spoke sieht.
func Run(ctx context.Context, src Source, tr *Tracker, flush func(Aggregate) error) error {
    events, err := src.Events(ctx)
    if err != nil {
        return err
    }
    ticker := time.NewTicker(tr.cfg.FlushInterval)
    defer ticker.Stop()
    for {
        select {
        case <-ctx.Done():
            return ctx.Err()
        case e, ok := <-events:
            if !ok {
             // Quelle still: letzten Zustand nicht verschlucken,
             // ein finaler Flush - danach sauber beenden (Agent entscheidet Retry).
            return flush(tr.Snapshot())
						}
            tr.Ingest(e)
        case <-ticker.C:
            if err := flush(tr.Snapshot()); err != nil {
                return err // RetryPublisher des Agents entscheidet Wiederholung
            }
        }
    }
}
