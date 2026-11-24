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