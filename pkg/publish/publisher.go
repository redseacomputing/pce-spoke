package publish

import "context"

// ScanResult ist das transportierbare Ergebnis eines Sensordurchlaufs:
// das fertige OSCAL-Assessment-Results-Dokument nebst Metadaten.
type ScanResult struct {
	// OSCAL ist das vollstaendige OSCAL 1.1.2 Assessment Results JSON.
	OSCAL []byte
	// Sensor identifiziert die Quelle ("kubescape", spaeter "falco").
	Sensor string
	// Timestamp ist der Zeitpunkt des Sensorlaufs (UTC).
	Timestamp string
	// SchemaVersion versioniert den Transportvertrag.
	SchemaVersion string
}

// Publisher ist die einzige Transport-Abstraktion des Agents.
//
// M1: ConfigMapPublisher - schreibt die Scan-Quelle im Hub-Cluster,
// die der Hub-Controller per spec.scanConfigMapRef liest.
// Spaeter: NATSPublisher - CloudEvents auf NATS (Guiding Test 3, Falco-Streaming).
//
// Implementierungen MUSSEN:
//   - bei Transientfehlern einen Fehler zurueckgeben (Retry gehoert zum Caller),
//   - nie selbst crashen oder os.Exit aufrufen,
//   - nur die dem Spoke zugewiesene Ziel-Ressource schreiben (Datensouveraenitaet).
type Publisher interface {
	Publish(ctx context.Context, result ScanResult) error
}
