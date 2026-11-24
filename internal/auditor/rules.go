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