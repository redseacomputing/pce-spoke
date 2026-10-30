package publish

import (
    "context"
    "fmt"

    corev1 "k8s.io/api/core/v1"
    apierrors "k8s.io/apimachinery/pkg/api/errors"
    "k8s.io/apimachinery/pkg/runtime"
    "k8s.io/apimachinery/pkg/types"
    "sigs.k8s.io/controller-runtime/pkg/client"
)

const oscalKey = "oscal"

// ConfigMapPublisher schreibt Scan-Ergebnisse in eine ConfigMap im Hub-Cluster.
// Das ist die Quelle, die der Hub-Controller per spec.scanConfigMapRef liest.
type ConfigMapPublisher struct {
    Client client.Client
    // Namespace und Name der Ziel-ConfigMap im Hub.
    Namespace string
    Name      string
}

// NewConfigMapPublisher baut den Publisher inkl. Scheme-Registrierung.
func NewConfigMapPublisher(c client.Client, namespace, name string) *ConfigMapPublisher {
    return &ConfigMapPublisher{Client: c, Namespace: namespace, Name: name}
}

// Publish schreibt das OSCAL-Dokument in die Ziel-ConfigMap (Get-or-Create, dann Update).
func (p *ConfigMapPublisher) Publish(ctx context.Context, result ScanResult) error {
    key := types.NamespacedName{Namespace: p.Namespace, Name: p.Name}

    cm := &corev1.ConfigMap{}
    err := p.Client.Get(ctx, key, cm)
    if apierrors.IsNotFound(err) {
        cm = &corev1.ConfigMap{}
        cm.Namespace = p.Namespace
        cm.Name = p.Name
        cm.Labels = map[string]string{"app.kubernetes.io/managed-by": "pce-spoke"}
        cm.Data = map[string]string{
            oscalKey:          string(result.OSCAL),
            "sensor":          result.Sensor,
            "lastHeartbeat":   result.Timestamp,
            "schemaVersion":   result.SchemaVersion,
        }
        return p.Client.Create(ctx, cm)
    }
    if err != nil {
        return fmt.Errorf("get configmap %s/%s: %w", p.Namespace, p.Name, err)
    }

    if cm.Data == nil {
        cm.Data = map[string]string{}
    }
    cm.Data[oscalKey] = string(result.OSCAL)
    cm.Data["sensor"] = result.Sensor
    cm.Data["lastHeartbeat"] = result.Timestamp
    cm.Data["schemaVersion"] = result.SchemaVersion
    return p.Client.Update(ctx, cm)
}

var _ = runtime.Object(nil) // Schema-Kompatibilitätsanker; entfernen, falls ungenutzt angemeckert wird
