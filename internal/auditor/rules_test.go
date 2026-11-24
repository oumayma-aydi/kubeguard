package auditor

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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