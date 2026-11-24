package auditor

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

// insecurePod viole les 4 règles à la fois.
func insecurePod() *corev1.Pod {
	return newPod(corev1.Container{
		Name:            "app",
		Image:           "nginx:latest",
		SecurityContext: &corev1.SecurityContext{Privileged: boolPtr(true)},
	})
}

// securePod respecte les 4 règles.
func securePod() *corev1.Pod {
	c := ctrWithLimits("app", "500m", "128Mi")
	c.Image = "nginx:1.27.4"
	c.SecurityContext = &corev1.SecurityContext{
		Privileged:   boolPtr(false),
		RunAsNonRoot: boolPtr(true),
	}
	return newPod(c)
}

func TestAudit(t *testing.T) {
	all := []string{"privileged", "runAsNonRoot", "latestImage", "resourceLimits"}

	tests := []struct {
		name    string
		pod     *corev1.Pod
		enabled []string
		want    int // nombre de findings
	}{
		{"T11 pod fautif, 4 règles", insecurePod(), all, 4},
		{"T07 pod sécurisé, 4 règles", securePod(), all, 0},
		{"T08 une seule règle activée", insecurePod(), []string{"privileged"}, 1},
		{"aucune règle activée", insecurePod(), nil, 0},
		{"règle inconnue ignorée", insecurePod(), []string{"nimportequoi"}, 0},
		{"doublon dans la liste", insecurePod(), []string{"privileged", "privileged"}, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Audit(tt.pod, tt.enabled)
			if len(got) != tt.want {
				t.Fatalf("attendu %d finding(s), obtenu %d", tt.want, len(got))
			}
		})
	}
}

func TestIsCompliant(t *testing.T) {
	all := []string{"privileged", "runAsNonRoot", "latestImage", "resourceLimits"}
	if IsCompliant(Audit(insecurePod(), all)) {
		t.Error("le pod fautif ne doit pas être conforme")
	}
	if !IsCompliant(Audit(securePod(), all)) {
		t.Error("le pod sécurisé doit être conforme")
	}
}
