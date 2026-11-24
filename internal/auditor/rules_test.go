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