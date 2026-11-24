package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/oumayma-aydi/kubeguard/internal/state"
)

// Collector calcule les métriques à partir de l'état courant.
type Collector struct {
	store *state.Store

	podsCompliant    *prometheus.Desc
	podsNonCompliant *prometheus.Desc
	findingsActive   *prometheus.Desc
	findingsBySev    *prometheus.Desc
	ruleViolations   *prometheus.Desc
}

func NewCollector(s *state.Store) *Collector {
	return &Collector{
		store: s,
		podsCompliant: prometheus.NewDesc("kubeguard_pods_compliant",
			"Number of compliant pods per namespace.", []string{"namespace"}, nil),
		podsNonCompliant: prometheus.NewDesc("kubeguard_pods_noncompliant",
			"Number of non-compliant pods per namespace.", []string{"namespace"}, nil),
		findingsActive: prometheus.NewDesc("kubeguard_findings_active",
			"Active findings per namespace.", []string{"namespace"}, nil),
		findingsBySev: prometheus.NewDesc("kubeguard_findings_by_severity",
			"Active findings per severity.", []string{"severity"}, nil),
		ruleViolations: prometheus.NewDesc("kubeguard_rule_violations",
			"Active findings per rule.", []string{"rule_id", "rule_name"}, nil),
	}
}

func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.podsCompliant
	ch <- c.podsNonCompliant
	ch <- c.findingsActive
	ch <- c.findingsBySev
	ch <- c.ruleViolations
}

func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	snap := c.store.Snapshot()

	compliant := map[string]float64{}
	nonCompliant := map[string]float64{}
	findingsNS := map[string]float64{}
	bySev := map[string]float64{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
	type ruleKey struct{ id, name string }
	byRule := map[ruleKey]float64{}

	for key, findings := range snap {
		ns := namespaceOf(key)
		if len(findings) == 0 {
			compliant[ns]++
			continue
		}
		nonCompliant[ns]++
		findingsNS[ns] += float64(len(findings))
		for _, f := range findings {
			bySev[string(f.Severity)]++
			byRule[ruleKey{f.RuleID, f.RuleName}]++
		}
	}

	// Les namespaces sans Pod non conforme doivent quand même exposer 0.
	for ns := range compliant {
		if _, ok := nonCompliant[ns]; !ok {
			nonCompliant[ns] = 0
		}
		if _, ok := findingsNS[ns]; !ok {
			findingsNS[ns] = 0
		}
	}
	for ns := range nonCompliant {
		if _, ok := compliant[ns]; !ok {
			compliant[ns] = 0
		}
	}

	for ns, v := range compliant {
		ch <- prometheus.MustNewConstMetric(c.podsCompliant, prometheus.GaugeValue, v, ns)
	}
	for ns, v := range nonCompliant {
		ch <- prometheus.MustNewConstMetric(c.podsNonCompliant, prometheus.GaugeValue, v, ns)
	}
	for ns, v := range findingsNS {
		ch <- prometheus.MustNewConstMetric(c.findingsActive, prometheus.GaugeValue, v, ns)
	}
	for sev, v := range bySev {
		ch <- prometheus.MustNewConstMetric(c.findingsBySev, prometheus.GaugeValue, v, sev)
	}
	for k, v := range byRule {
		ch <- prometheus.MustNewConstMetric(c.ruleViolations, prometheus.GaugeValue, v, k.id, k.name)
	}
}

// namespaceOf extrait le namespace de la clé "namespace/nom".
func namespaceOf(key string) string {
	for i := 0; i < len(key); i++ {
		if key[i] == '/' {
			return key[:i]
		}
	}
	return key
}

// Register enregistre le collecteur dans le registre de controller-runtime,
// celui exposé par l'endpoint /metrics du manager.
func Register(s *state.Store) {
	metrics.Registry.MustRegister(NewCollector(s))
}
