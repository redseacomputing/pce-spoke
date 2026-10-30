package publish

import (
    "context"
    "testing"

    corev1 "k8s.io/api/core/v1"
    "k8s.io/apimachinery/pkg/runtime"
    "sigs.k8s.io/controller-runtime/pkg/client"
    "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func newTestClient(t *testing.T) client.Client {
    t.Helper()
    scheme := runtime.NewScheme()
    if err := corev1.AddToScheme(scheme); err != nil {
        t.Fatalf("scheme setup failed: %v", err)
    }
    return fake.NewClientBuilder().WithScheme(scheme).Build()
}

func TestPublisherWritesScanSource(t *testing.T) {
    ctx := context.Background()
    c := newTestClient(t)

    oscal := []byte(`{"assessment-results":{"metadata":{"title":"scan"}}}`)
    pub := NewConfigMapPublisher(c, "hub-system", "spoke-scan-source")

    err := pub.Publish(ctx, ScanResult{
        OSCAL:        oscal,
        Sensor:       "kubescape",
        Timestamp:    "2026-10-30T20:00:00Z",
        SchemaVersion: "1.0",
    })
    if err != nil {
        t.Fatalf("publish failed: %v", err)
    }

    // Assert: ConfigMap wurde angelegt und traegt den Vertrag
    cm := &corev1.ConfigMap{}
    if err := c.Get(ctx, client.ObjectKey{Namespace: "hub-system", Name: "spoke-scan-source"}, cm); err != nil {
        t.Fatalf("configmap not created: %v", err)
    }
    if cm.Data["oscal"] != string(oscal) {
        t.Errorf("oscal payload mismatch: got %q", cm.Data["oscal"])
    }
    if cm.Data["sensor"] != "kubescape" {
        t.Errorf("expected sensor 'kubescape', got %q", cm.Data["sensor"])
    }
    if cm.Data["lastHeartbeat"] != "2026-10-30T20:00:00Z" {
        t.Errorf("heartbeat mismatch: got %q", cm.Data["lastHeartbeat"])
    }
    if cm.Data["schemaVersion"] != "1.0" {
        t.Errorf("schemaVersion mismatch: got %q", cm.Data["schemaVersion"])
    }
}

func TestPublisherUpdatesExistingScanSource(t *testing.T) {
    // Zweiter Lauf aktualisiert dieselbe ConfigMap (Heartbeat-Refresh)
    ctx := context.Background()
    c := newTestClient(t)
    pub := NewConfigMapPublisher(c, "hub-system", "spoke-scan-source")

    first := ScanResult{OSCAL: []byte(`{"v":1}`), Sensor: "kubescape", Timestamp: "2026-10-30T20:00:00Z", SchemaVersion: "1.0"}
    if err := pub.Publish(ctx, first); err != nil {
        t.Fatalf("first publish failed: %v", err)
    }
    second := ScanResult{OSCAL: []byte(`{"v":2}`), Sensor: "kubescape", Timestamp: "2026-10-30T21:00:00Z", SchemaVersion: "1.0"}
    if err := pub.Publish(ctx, second); err != nil {
        t.Fatalf("second publish failed: %v", err)
    }

    cm := &corev1.ConfigMap{}
    if err := c.Get(ctx, client.ObjectKey{Namespace: "hub-system", Name: "spoke-scan-source"}, cm); err != nil {
        t.Fatalf("get failed: %v", err)
    }
    if cm.Data["oscal"] != `{"v":2}` {
        t.Errorf("expected updated oscal, got %q", cm.Data["oscal"])
    }
    if cm.Data["lastHeartbeat"] != "2026-10-30T21:00:00Z" {
        t.Errorf("expected refreshed heartbeat, got %q", cm.Data["lastHeartbeat"])
    }
}
