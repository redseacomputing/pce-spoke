package publish

import (
    "context"
    "encoding/json"
    "fmt"
		"time"

    "github.com/redseacomputing/pce-spoke/pkg/threat"
    corev1 "k8s.io/api/core/v1"
    apierrors "k8s.io/apimachinery/pkg/api/errors"
    "k8s.io/apimachinery/pkg/types"
    "sigs.k8s.io/controller-runtime/pkg/client"
)

const threatKey = "threat" // muss zum Hub-Default (ThreatConfigMapKey) passen

// ThreatPublisher schreibt das Falco-Aggregat in die Threat-ConfigMap im
// Hub-Cluster - die Quelle, die der Hub-Controller per spec.threatConfigMapRef
// liest (GT3-Vertrag). Symmetrisch zum ConfigMapPublisher (M1).
type ThreatPublisher struct {
    Client    client.Client
    Namespace string
    Name      string
}

func NewThreatPublisher(c client.Client, namespace, name string) *ThreatPublisher {
    return &ThreatPublisher{Client: c, Namespace: namespace, Name: name}
}

// Publish schreibt das Aggregat (Get-or-Create, dann Update).
func (p *ThreatPublisher) Publish(ctx context.Context, agg threat.Aggregate) error {
    payload, err := json.Marshal(agg)
    if err != nil {
        return fmt.Errorf("marshal threat aggregate: %w", err)
    }

    key := types.NamespacedName{Namespace: p.Namespace, Name: p.Name}
    cm := &corev1.ConfigMap{}
    err = p.Client.Get(ctx, key, cm)
    if apierrors.IsNotFound(err) {
        cm = &corev1.ConfigMap{}
        cm.Namespace = p.Namespace
        cm.Name = p.Name
        cm.Labels = map[string]string{"app.kubernetes.io/managed-by": "pce-spoke"}
        cm.Data = map[string]string{
            threatKey:        string(payload),
            "schemaVersion":   agg.SchemaVersion,
            "lastHeartbeat":   agg.GeneratedAt.UTC().Format(time.RFC3339),
        }
        return p.Client.Create(ctx, cm)
    }
    if err != nil {
        return fmt.Errorf("get threat configmap %s/%s: %w", p.Namespace, p.Name, err)
    }

    if cm.Data == nil {
        cm.Data = map[string]string{}
    }
    cm.Data[threatKey] = string(payload)
    cm.Data["schemaVersion"] = agg.SchemaVersion
    cm.Data["lastHeartbeat"] = agg.GeneratedAt.UTC().Format(time.RFC3339)
    return p.Client.Update(ctx, cm)
}
