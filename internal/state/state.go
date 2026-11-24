package state

import (
	"sync"

	"github.com/oumayma-aydi/kubeguard/internal/auditor"
)

// Store garde, pour chaque Pod audité, ses findings actuels.
// Il est protégé par un mutex car le controller peut réconcilier en parallèle.
type Store struct {
	mu   sync.RWMutex
	pods map[string][]auditor.Finding // clé : "namespace/nom"
}

func NewStore() *Store {
	return &Store{pods: make(map[string][]auditor.Finding)}
}

// Set enregistre le résultat d'audit d'un Pod (remplace le précédent).
func (s *Store) Set(key string, findings []auditor.Finding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pods[key] = findings
}

// Delete retire un Pod (supprimé du cluster) : scénario T10.
func (s *Store) Delete(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.pods, key)
}

// Snapshot renvoie une copie : l'appelant peut la lire sans verrou.
func (s *Store) Snapshot() map[string][]auditor.Finding {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string][]auditor.Finding, len(s.pods))
	for k, v := range s.pods {
		out[k] = v
	}
	return out
}
