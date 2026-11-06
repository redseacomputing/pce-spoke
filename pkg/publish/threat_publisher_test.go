// Copyright 2026 Red Sea Computing GmbH. All rights reserved.
// Use of this source code is governed by Apache 2.0 license that can be found in the LICENSE file.

package publish_test

import (
	"context"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/redseacomputing/pce-spoke/pkg/publish"
	"github.com/redseacomputing/pce-spoke/pkg/threat"
)

var _ = Describe("ThreatPublisher Guiding Test", func() {
	var (
		k8sClient  client.Client
		testEnv    *envtest.Environment
		ctx        context.Context
		cancel     context.CancelFunc
		publisher  *publish.ThreatPublisher
		hubNS      = "pce-hub-system"
		threatData = threat.Aggregate{
			SchemaVersion:     "1",
			ActiveThreatCount: 1,
			Threats: []threat.Threat{
				{
					Rule:      "TestRule",
					Container: "test-container",
					Count:     1,
					FirstSeen: time.Now().Add(-10 * time.Minute),
					LastSeen:  time.Now(),
				},
			},
			GeneratedAt: time.Now(),
		}
	)

	BeforeEach(func() {
		ctx, cancel = context.WithCancel(context.TODO())

		// envtest-Umgebung starten
		testEnv = &envtest.Environment{
			CRDDirectoryPaths:     []string{}, // Keine CRDs benötigt
			ErrorIfCRDPathMissing: false,
		}

		cfg, err := testEnv.Start()
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg).NotTo(BeNil())

		// Kubernetes-Client initialisieren
		k8sClient, err = client.New(cfg, client.Options{Scheme: scheme.Scheme})
		Expect(err).NotTo(HaveOccurred())
		Expect(k8sClient).NotTo(BeNil())

		// Namespace pce-hub-system erstellen
		hubNamespace := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: hubNS},
		}
		Expect(k8sClient.Create(ctx, hubNamespace)).Should(Succeed())

		// ThreatPublisher initialisieren
		publisher = publish.NewThreatPublisher(k8sClient, hubNS, "threat-source")
	})

	AfterEach(func() {
		cancel()
		Expect(testEnv.Stop()).Should(Succeed())
	})

	It("should publish threat data to ConfigMap 'threat-source'", func() {
		// WHEN: Threat-Daten werden veröffentlicht
		Expect(publisher.Publish(ctx, threatData)).Should(Succeed())

		// THEN: ConfigMap 'threat-source' enthält die korrekten Daten
		var cm corev1.ConfigMap
		Expect(k8sClient.Get(ctx, client.ObjectKey{Name: "threat-source", Namespace: hubNS}, &cm)).Should(Succeed())

		// Vertragsprüfung: JSON-Struktur und SchemaVersion
		Expect(cm.Data).To(HaveKey("threat"))
		Expect(cm.Data["threat"]).To(ContainSubstring("\"schemaVersion\":\"1\""))
		Expect(cm.Data["threat"]).To(ContainSubstring("\"activeThreatCount\":1"))
		Expect(cm.Data["threat"]).To(ContainSubstring("\"rule\":\"TestRule\""))
	})
})

func TestThreatPublisher(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "ThreatPublisher Guiding Test Suite")
}