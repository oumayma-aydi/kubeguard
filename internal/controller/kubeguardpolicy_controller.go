/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	securityv1alpha1 "github.com/oumayma-aydi/kubeguard/api/v1alpha1"
	"github.com/oumayma-aydi/kubeguard/internal/auditor"
	"github.com/oumayma-aydi/kubeguard/internal/state"
)

// Namespaces système ignorés par l'audit.
var ignoredNamespaces = map[string]bool{
	"kube-system":        true,
	"kube-public":        true,
	"kube-node-lease":    true,
	"kubeguard-system":   true,
	"local-path-storage": true,
}

// KubeGuardPolicyReconciler audite les Pods selon la KubeGuardPolicy active.
type KubeGuardPolicyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Store  *state.Store
}

// +kubebuilder:rbac:groups=security.kubeguard.io,resources=kubeguardpolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch

// Reconcile est appelé pour un Pod (créé, modifié ou supprimé).
func (r *KubeGuardPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	key := req.Namespace + "/" + req.Name

	if ignoredNamespaces[req.Namespace] {
		return ctrl.Result{}, nil
	}

	var pod corev1.Pod
	if err := r.Get(ctx, req.NamespacedName, &pod); err != nil {
		if apierrors.IsNotFound(err) {
			// Pod supprimé : on retire son état (T10).
			r.Store.Delete(key)
			log.Info("pod deleted, state removed", "pod", key)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// Un Pod terminé n'est plus une charge de travail active.
	if pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
		r.Store.Delete(key)
		return ctrl.Result{}, nil
	}

	// Policy active : la première trouvée dans le cluster (option A du MVP).
	var policies securityv1alpha1.KubeGuardPolicyList
	if err := r.List(ctx, &policies); err != nil {
		return ctrl.Result{}, err
	}
	if len(policies.Items) == 0 {
		r.Store.Delete(key) // pas de policy : rien à auditer
		return ctrl.Result{}, nil
	}
	enabled := make([]string, 0, len(policies.Items[0].Spec.EnabledRules))
	for _, rule := range policies.Items[0].Spec.EnabledRules {
		enabled = append(enabled, string(rule))
	}

	findings := auditor.Audit(&pod, enabled)
	r.Store.Set(key, findings)

	if auditor.IsCompliant(findings) {
		log.Info("pod COMPLIANT", "pod", key)
	} else {
		log.Info("pod NON-COMPLIANT", "pod", key, "findings", len(findings))
		for _, f := range findings {
			log.Info("finding",
				"rule", f.RuleID, "severity", f.Severity,
				"container", f.ContainerName, "message", f.Message)
		}
	}
	return ctrl.Result{}, nil
}

// SetupWithManager : Pod = ressource principale, policy = déclencheur secondaire.
func (r *KubeGuardPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Pod{}).
		Watches(&securityv1alpha1.KubeGuardPolicy{},
			handler.EnqueueRequestsFromMapFunc(r.allPods)).
		Named("kubeguard-pods").
		Complete(r)
}

// allPods : quand une policy change, on remet tous les Pods en file.
func (r *KubeGuardPolicyReconciler) allPods(ctx context.Context, _ client.Object) []reconcile.Request {
	var pods corev1.PodList
	if err := r.List(ctx, &pods); err != nil {
		return nil
	}
	reqs := make([]reconcile.Request, 0, len(pods.Items))
	for _, p := range pods.Items {
		reqs = append(reqs, reconcile.Request{
			NamespacedName: types.NamespacedName{Namespace: p.Namespace, Name: p.Name},
		})
	}
	return reqs
}
