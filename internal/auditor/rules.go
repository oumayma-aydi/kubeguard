package auditor

import corev1 "k8s.io/api/core/v1"

// Rule est une fonction qui inspecte un Pod et retourne ses violations.
type Rule func(pod *corev1.Pod) []Finding

// allContainers renvoie tous les conteneurs du Pod :
// conteneurs d'init, éphémères et principaux.
func allContainers(pod *corev1.Pod) []corev1.Container {
	var out []corev1.Container
	out = append(out, pod.Spec.InitContainers...)
	out = append(out, pod.Spec.Containers...)
	for _, ec := range pod.Spec.EphemeralContainers {
		out = append(out, corev1.Container(ec.EphemeralContainerCommon))
	}
	return out
}

// CheckPrivileged implémente KG-001.
func CheckPrivileged(pod *corev1.Pod) []Finding {
	var findings []Finding
	for _, c := range allContainers(pod) {
		sc := c.SecurityContext
		if sc != nil && sc.Privileged != nil && *sc.Privileged {
			findings = append(findings, Finding{
				RuleID:         "KG-001",
				RuleName:       "Privileged Container",
				Severity:       SeverityCritical,
				Namespace:      pod.Namespace,
				PodName:        pod.Name,
				ContainerName:  c.Name,
				Message:        "Privileged container detected",
				Recommendation: "Set securityContext.privileged to false",
			})
		}
	}
	return findings
}

// CheckRunAsNonRoot implémente KG-002.
// La valeur du conteneur prime sur celle du Pod ; si aucune des deux
// n'impose runAsNonRoot=true, le conteneur est signalé.
func CheckRunAsNonRoot(pod *corev1.Pod) []Finding {
	var podLevel *bool
	if pod.Spec.SecurityContext != nil {
		podLevel = pod.Spec.SecurityContext.RunAsNonRoot
	}

	var findings []Finding
	for _, c := range allContainers(pod) {
		effective := podLevel // valeur héritée par défaut
		if c.SecurityContext != nil && c.SecurityContext.RunAsNonRoot != nil {
			effective = c.SecurityContext.RunAsNonRoot // le conteneur écrase
		}

		if effective == nil || !*effective {
			findings = append(findings, Finding{
				RuleID:         "KG-002",
				RuleName:       "Root Execution",
				Severity:       SeverityHigh,
				Namespace:      pod.Namespace,
				PodName:        pod.Name,
				ContainerName:  c.Name,
				Message:        "runAsNonRoot is not enforced for this container",
				Recommendation: "Set securityContext.runAsNonRoot to true",
			})
		}
	}
	return findings
}