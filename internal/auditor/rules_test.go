package auditor

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1" 
	resource "k8s.io/apimachinery/pkg/api/resource"
)

func boolPtr(b bool) *bool { return &b }

func newPod(containers ...corev1.Container) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "kubeguard-demo"},
		Spec:       corev1.PodSpec{Containers: containers},
	}
}

func TestCheckPrivileged(t *testing.T) {
	tests := []struct {
		name string
		pod  *corev1.Pod
		want int
	}{
		{
			name: "privileged true",
			pod: newPod(corev1.Container{
				Name:            "app",
				SecurityContext: &corev1.SecurityContext{Privileged: boolPtr(true)},
			}),
			want: 1,
		},
		{
			name: "privileged false",
			pod: newPod(corev1.Container{
				Name:            "app",
				SecurityContext: &corev1.SecurityContext{Privileged: boolPtr(false)},
			}),
			want: 0,
		},
		{
			name: "pas de securityContext",
			pod:  newPod(corev1.Container{Name: "app"}),
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CheckPrivileged(tt.pod)
			if len(got) != tt.want {
				t.Fatalf("attendu %d finding(s), obtenu %d", tt.want, len(got))
			}
			if tt.want > 0 && got[0].Severity != SeverityCritical {
				t.Errorf("sévérité attendue CRITICAL, obtenue %s", got[0].Severity)
			}
		})
	}
}

func newPodWithSC(podSC *corev1.PodSecurityContext, containers ...corev1.Container) *corev1.Pod {
	p := newPod(containers...)
	p.Spec.SecurityContext = podSC
	return p
}

func ctrWithNonRoot(name string, v *bool) corev1.Container {
	c := corev1.Container{Name: name}
	if v != nil {
		c.SecurityContext = &corev1.SecurityContext{RunAsNonRoot: v}
	}
	return c
}

func TestCheckRunAsNonRoot(t *testing.T) {
	tests := []struct {
		name string
		pod  *corev1.Pod
		want []string // noms des conteneurs en violation
	}{
		{"rien de défini", newPod(ctrWithNonRoot("app", nil)), []string{"app"}},
		{"conteneur true", newPod(ctrWithNonRoot("app", boolPtr(true))), nil},
		{"conteneur false", newPod(ctrWithNonRoot("app", boolPtr(false))), []string{"app"}},
		{"pod true, conteneur absent (hérité)",
			newPodWithSC(&corev1.PodSecurityContext{RunAsNonRoot: boolPtr(true)}, ctrWithNonRoot("app", nil)), nil},
		{"pod true, conteneur false (écrase)",
			newPodWithSC(&corev1.PodSecurityContext{RunAsNonRoot: boolPtr(true)}, ctrWithNonRoot("app", boolPtr(false))), []string{"app"}},
		{"pod false, conteneur true (écrase)",
			newPodWithSC(&corev1.PodSecurityContext{RunAsNonRoot: boolPtr(false)}, ctrWithNonRoot("app", boolPtr(true))), nil},
		{"pod false, conteneur absent",
			newPodWithSC(&corev1.PodSecurityContext{RunAsNonRoot: boolPtr(false)}, ctrWithNonRoot("app", nil)), []string{"app"}},
		{"deux conteneurs, un seul fautif",
			newPod(ctrWithNonRoot("ok", boolPtr(true)), ctrWithNonRoot("bad", nil)), []string{"bad"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CheckRunAsNonRoot(tt.pod)
			if len(got) != len(tt.want) {
				t.Fatalf("attendu %d finding(s), obtenu %d", len(tt.want), len(got))
			}
			for i, f := range got {
				if f.ContainerName != tt.want[i] {
					t.Errorf("conteneur attendu %q, obtenu %q", tt.want[i], f.ContainerName)
				}
				if f.RuleID != "KG-002" || f.Severity != SeverityHigh {
					t.Errorf("RuleID/Severity inattendus: %s / %s", f.RuleID, f.Severity)
				}
			}
		})
	}
}

func ctrWithImage(name, image string) corev1.Container {
	return corev1.Container{Name: name, Image: image}
}

func TestCheckImageTag(t *testing.T) {
	tests := []struct {
		name  string
		image string
		bad   bool
	}{
		{"sans tag", "nginx", true},
		{"tag latest", "nginx:latest", true},
		{"tag fixe", "nginx:1.27.4", false},
		{"tag court", "redis:7.2", false},
		{"registry avec port, sans tag", "localhost:5000/nginx", true},
		{"registry avec port, tag fixe", "localhost:5000/nginx:1.27", false},
		{"registry avec port, latest", "localhost:5000/nginx:latest", true},
		{"digest seul", "nginx@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", false},
		{"tag latest + digest", "nginx:latest@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", false},
		{"LATEST en majuscules", "nginx:LATEST", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CheckImageTag(newPod(ctrWithImage("app", tt.image)))
			if tt.bad && len(got) != 1 {
				t.Fatalf("image %q : 1 finding attendu, obtenu %d", tt.image, len(got))
			}
			if !tt.bad && len(got) != 0 {
				t.Fatalf("image %q : aucun finding attendu, obtenu %d", tt.image, len(got))
			}
			if tt.bad && (got[0].RuleID != "KG-003" || got[0].Severity != SeverityMedium) {
				t.Errorf("RuleID/Severity inattendus: %s / %s", got[0].RuleID, got[0].Severity)
			}
		})
	}
}

func ctrWithLimits(name string, cpu, mem string) corev1.Container {
	limits := corev1.ResourceList{}
	if cpu != "" {
		limits[corev1.ResourceCPU] = resource.MustParse(cpu)
	}
	if mem != "" {
		limits[corev1.ResourceMemory] = resource.MustParse(mem)
	}
	return corev1.Container{
		Name:      name,
		Resources: corev1.ResourceRequirements{Limits: limits},
	}
}

func TestCheckResourceLimits(t *testing.T) {
	tests := []struct {
		name    string
		ctr     corev1.Container
		wantBad bool
		wantMsg string // sous-chaîne attendue dans le message
	}{
		{"cpu et mémoire présents", ctrWithLimits("app", "500m", "128Mi"), false, ""},
		{"cpu absent", ctrWithLimits("app", "", "128Mi"), true, "CPU"},
		{"mémoire absente", ctrWithLimits("app", "500m", ""), true, "memory"},
		{"les deux absents", ctrWithLimits("app", "", ""), true, "CPU and memory"},
		{"limit à zéro = absent", ctrWithLimits("app", "0", "128Mi"), true, "CPU"},
		{"requests seules, pas de limits",
			corev1.Container{
				Name: "app",
				Resources: corev1.ResourceRequirements{
					Requests: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("64Mi")},
				},
			}, true, "CPU and memory"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CheckResourceLimits(newPod(tt.ctr))
			if !tt.wantBad {
				if len(got) != 0 {
					t.Fatalf("aucun finding attendu, obtenu %d", len(got))
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("1 finding attendu, obtenu %d", len(got))
			}
			if got[0].RuleID != "KG-004" || got[0].Severity != SeverityMedium {
				t.Errorf("RuleID/Severity inattendus: %s / %s", got[0].RuleID, got[0].Severity)
			}
			if !strings.Contains(got[0].Message, tt.wantMsg) {
				t.Errorf("message %q devrait contenir %q", got[0].Message, tt.wantMsg)
			}
		})
	}
}
