package auditor

// Severity est le niveau de criticité d'un finding.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
)

// Finding décrit une violation détectée sur un conteneur.
type Finding struct {
	RuleID         string
	RuleName       string
	Severity       Severity
	Namespace      string
	PodName        string
	ContainerName  string
	Message        string
	Recommendation string
}
