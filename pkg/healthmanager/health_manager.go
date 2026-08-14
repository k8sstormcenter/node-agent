package healthmanager

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/kubescape/node-agent/pkg/containerwatcher"
	"github.com/kubescape/node-agent/pkg/signature/bundle"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

type HealthManager struct {
	containerWatcher containerwatcher.ContainerWatcher
	port             int
	// policyStatus reports the trust policy in force; nil getter or nil
	// snapshot serves 404. Digests, mode and counts only — never the policy
	// body or signer lists (this port is unauthenticated).
	policyStatus func() *bundle.PolicyStatus
}

func NewHealthManager() *HealthManager {
	return &HealthManager{
		port: 7888,
	}
}

func (h *HealthManager) SetContainerWatcher(containerWatcher containerwatcher.ContainerWatcher) {
	h.containerWatcher = containerWatcher
}

func (h *HealthManager) SetPolicyStatus(getter func() *bundle.PolicyStatus) {
	h.policyStatus = getter
}

func (h *HealthManager) policyzHandler(w http.ResponseWriter, _ *http.Request) {
	if h.policyStatus == nil {
		http.NotFound(w, nil)
		return
	}
	s := h.policyStatus()
	if s == nil {
		http.NotFound(w, nil)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s)
}

func (h *HealthManager) Start(ctx context.Context) {
	go func() {
		http.HandleFunc("/livez", h.livenessProbe)
		http.HandleFunc("/readyz", h.readinessProbe)
		http.HandleFunc("/policyz", h.policyzHandler)
		srv := &http.Server{
			Addr:         fmt.Sprintf(":%d", h.port),
			WriteTimeout: 15 * time.Second,
			ReadTimeout:  15 * time.Second,
		}
		logger.L().Info("starting health manager", helpers.Int("port", h.port))
		if err := srv.ListenAndServe(); err != nil {
			logger.L().Ctx(ctx).Fatal("HealthManager - failed to start", helpers.Error(err), helpers.Int("port", h.port))
		}
	}()
}

func (h *HealthManager) livenessProbe(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func (h *HealthManager) readinessProbe(w http.ResponseWriter, _ *http.Request) {
	if h.containerWatcher != nil && h.containerWatcher.Ready() {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusInternalServerError)
}
