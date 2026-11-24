package auditor

import (
	"strings"

	corev1 "k8s.io/api/core/v1"
)

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

// isPinned indique si une référence d'image est fixée par tag (≠ latest) ou par digest.
func isPinned(image string) bool {
	// Un digest fixe l'image de façon immuable.
	if strings.Contains(image, "@") {
		return true
	}
	// Le tag suit le dernier ":" situé après le dernier "/".
	// Sinon le ":" appartient au port du registry (ex: localhost:5000/nginx).
	lastSlash := strings.LastIndex(image, "/")
	lastColon := strings.LastIndex(image, ":")
	if lastColon <= lastSlash {
		return false // aucun tag
	}
	tag := image[lastColon+1:]
	return tag != "" && !strings.EqualFold(tag, "latest")
}

// CheckImageTag implémente KG-003.
func CheckImageTag(pod *corev1.Pod) []Finding {
	var findings []Finding
	for _, c := range allContainers(pod) {
		if !isPinned(c.Image) {
			findings = append(findings, Finding{
				RuleID:         "KG-003",
				RuleName:       "Unpinned Image",
				Severity:       SeverityMedium,
				Namespace:      pod.Namespace,
				PodName:        pod.Name,
				ContainerName:  c.Name,
				Message:        "Image " + c.Image + " uses the latest tag or no tag",
				Recommendation: "Use a specific version tag or an image digest",
			})
		}
	}
	return findings
}

// hasLimit indique si une limite non nulle est définie pour la ressource.
func hasLimit(c corev1.Container, name corev1.ResourceName) bool {
	q, ok := c.Resources.Limits[name]
	return ok && !q.IsZero()
}

// CheckResourceLimits implémente KG-004.
func CheckResourceLimits(pod *corev1.Pod) []Finding {
	var findings []Finding
	for _, c := range allContainers(pod) {
		noCPU := !hasLimit(c, corev1.ResourceCPU)
		noMem := !hasLimit(c, corev1.ResourceMemory)
		if !noCPU && !noMem {
			continue
		}

		var missing string
		switch {
		case noCPU && noMem:
			missing = "CPU and memory"
		case noCPU:
			missing = "CPU"
		default:
			missing = "memory"
		}

		findings = append(findings, Finding{
			RuleID:         "KG-004",
			RuleName:       "Missing Resource Limits",
			Severity:       SeverityMedium,
			Namespace:      pod.Namespace,
			PodName:        pod.Name,
			ContainerName:  c.Name,
			Message:        "Missing resource limits: " + missing,
			Recommendation: "Set resources.limits for " + missing,
		})
	}
	return findings
}