package threat

import (
    "context"

    "github.com/falcosecurity/client-go/pkg/client"
		"github.com/falcosecurity/client-go/pkg/api/outputs"
)

// NewGRPCSource liefert die Produktions-Source: subscribed auf den
// Falco-gRPC-Unix-Socket des eigenen Pods (Sidecar-Topologie).
func NewGRPCSource(unixSocketPath string) Source {
    return &grpcSource{unixSocketPath: unixSocketPath}
}

type grpcSource struct {
    unixSocketPath string
}

func (g *grpcSource) Events(ctx context.Context) (<-chan Event, error) {
    falco, err := client.NewForConfig(ctx, &client.Config{
        UnixSocketPath: g.unixSocketPath, // z. B. "unix:///run/falco/falco.sock"
    })
    if err != nil {
        return nil, err
    }

    outputs, err := falco.Outputs()
    if err != nil {
        falco.Close()
        return nil, err
    }
    stream, err := outputs.Sub(ctx) // Falco-RPC heisst wirklich "Sub"
    if err != nil {
        falco.Close()
        return nil, err
    }

    out := make(chan Event)
    go func() {
        defer close(out) // Stream zu -> Kanal zu -> Run macht finalen Flush
        defer falco.Close()
        for {
            resp, err := stream.Recv()
            if err != nil {
                return // ctx zu oder Socket tot: Abbruch ist ok
            }
            out <- eventFromFalco(resp)
        }
    }()
    return out, nil
}

// eventFromFalco reduziert die Falco-Response auf den Vertragstyp Event.
// OutputFields ist map[string]string; fehlt die Container-ID (Host-Event),
// landet das Aggregat unter "host".
func eventFromFalco(resp *outputs.Response) Event {
    container := "host"
    if id := resp.OutputFields["container.id"]; id != "" {
        container = id
    }
    time := resp.Time.AsTime()
    return Event{
        Rule:      resp.Rule,
        Container: container,
        Time:      time,
        Output:    resp.Output,
    }
}
