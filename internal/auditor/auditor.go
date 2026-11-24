package auditor

import corev1 "k8s.io/api/core/v1"

// registry associe le nom d'une règle (celui de la CRD) à sa fonction.
var registry = map[string]Rule{
	"privileged":     CheckPrivileged,
	"runAsNonRoot":   CheckRunAsNonRoot,
	"latestImage":    CheckImageTag,
	"resourceLimits": CheckResourceLimits,
}

// Audit exécute uniquement les règles activées sur le Pod.
// Les noms inconnus sont ignorés (la CRD les refuse déjà à l'apply),
// et un nom répété n'est exécuté qu'une fois.
func Audit(pod *corev1.Pod, enabledRules []string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, name := range enabledRules {
		if seen[name] {
			continue
		}
		seen[name] = true

		rule, ok := registry[name]
		if !ok {
			continue
		}
		findings = append(findings, rule(pod)...)
	}
	return findings
}

// IsCompliant : un Pod est conforme s'il n'a aucun finding.
func IsCompliant(findings []Finding) bool {
	return len(findings) == 0
}
