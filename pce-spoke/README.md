# pce-spoke

PCE Spoke Agent - die Spoke-Seite der Policy Crosswalk Engine (PCE) Hub & Spoke Architektur.

## Zweck

Der Agent laeuft im Spoke-Cluster, konvertiert Sensor-Ausgaben (M1: Kubescape, spaeter Falco)
in OSCAL 1.1.2 Assessment Results und *pusht* sie an den Management Hub
(`redseacomputing/pce-hub`). Der Hub pollt niemals die Spokes.

## Architektur-Prinzipien

- **Push, kein Pull:** Verbindungsrichtung ist immer Spoke -> Hub (Firewall-freundlich,
  der Hub verwaltet keine Spoke-Credentials).
- **Transport austauschbar:** Der Agent kennt nur das `Publisher`-Interface.
  M1: `ConfigMapPublisher` (schreibt in die Hub-Quelle, die der Hub per
  `scanConfigMapRef` liest). Geplant: `NATSPublisher` (CloudEvents auf NATS)
  fuer das Event-Driven Streaming (Guiding Test 3, Falco).
- **Vertragsschutz:** Der Konverter wird gegen den Parser der pce-Library getestet
  (`TestKubescapeOutputToOSCAL`) - die Nahtstelle Spoke<->Hub ist damit
  gegen Schema-Drift gesichert.
- **Resilienz:** Sensor- und Publisher-Fehler werden geloggt und retryt,
  der Agent stuerzt nicht ab (Spiegelstueck zu Hub-Guiding-Test 4).
- **Keine Remediation:** Der Agent liest Sensoren und schreibt Ergebnisse.
  Er steuert niemals Ressourcen im Spoke oder Hub.

## Pakete

| Paket | Zweck |
|---|---|
| `pkg/convert` | Kubescape-JSON -> OSCAL 1.1.2 |
| `pkg/publish` | Publisher-Interface + Implementierungen |
| `cmd/agent` | Scheduler (Ticker), Retry-Loop, Wiring |

## M1-Meilenstein

1. `TestKubescapeOutputToOSCAL` - Konverter, validiert gegen den Hub-Parser
2. `TestPublisherWritesScanSource` - ConfigMapPublisher schreibt in die Hub-Quelle
3. `TestPublisherFailureIsContained` - Fehler werden gepuffert/retryt, kein Crash

Sobald M1 gruen ist, wird der Skip im Hub-Guiding-Test 4 entfernt.
