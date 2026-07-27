package clashapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

type ruleProviderResponse struct {
	Type        string                      `json:"type"`
	VehicleType string                      `json:"vehicleType"`
	Name        string                      `json:"name"`
	Format      string                      `json:"format,omitempty"`
	UpdatedAt   time.Time                   `json:"updatedAt"`
	Revision    uint64                      `json:"revision"`
	IPCIDR      adapter.RuleSetIPCIDRExport `json:"ip_cidr"`
}

type ruleProviderEvent struct {
	Name     string `json:"name,omitempty"`
	Revision uint64 `json:"revision"`
}

func ruleProviderRouter(server *Server) http.Handler {
	r := chi.NewRouter()
	r.Get("/", getRuleProviders(server))
	r.Get("/events", watchRuleProviders(server))

	r.Route("/{name}", func(r chi.Router) {
		r.Use(parseProviderName, findRuleProviderByName(server))
		r.Get("/", getRuleProvider)
		r.Put("/", updateRuleProvider)
	})
	return r
}

func getRuleProviders(server *Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		ruleSets := serverRuleSets(server)
		providers := make(render.M, len(ruleSets))
		var revision uint64
		for _, ruleSet := range ruleSets {
			provider := ruleProviderInfo(ruleSet)
			providers[ruleSet.Name()] = provider
			revision += provider.Revision
		}
		render.JSON(w, r, render.M{
			"providers": providers,
			"revision":  revision,
		})
	}
}

func getRuleProvider(w http.ResponseWriter, r *http.Request) {
	ruleSet := r.Context().Value(CtxKeyRuleProvider).(adapter.RuleSet)
	render.JSON(w, r, ruleProviderInfo(ruleSet))
}

func updateRuleProvider(w http.ResponseWriter, r *http.Request) {
	ruleSet := r.Context().Value(CtxKeyRuleProvider).(adapter.RuleSet)
	if updater, isUpdater := ruleSet.(adapter.RuleSetUpdater); isUpdater {
		if err := updater.Update(); err != nil {
			render.Status(r, http.StatusServiceUnavailable)
			render.JSON(w, r, newError(err.Error()))
			return
		}
	}
	render.NoContent(w, r)
}

func findRuleProviderByName(server *Server) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			name := r.Context().Value(CtxKeyProviderName).(string)
			ruleSet, exists := server.router.RuleSet(name)
			if !exists {
				render.Status(r, http.StatusNotFound)
				render.JSON(w, r, ErrNotFound)
				return
			}
			ctx := context.WithValue(r.Context(), CtxKeyRuleProvider, ruleSet)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func ruleProviderInfo(ruleSet adapter.RuleSet) ruleProviderResponse {
	var snapshot adapter.RuleSetProviderSnapshot
	if provider, loaded := ruleSet.(adapter.RuleSetProvider); loaded {
		snapshot = provider.ProviderSnapshot()
	}
	return ruleProviderResponse{
		Type:        "Rule",
		VehicleType: ruleProviderVehicleType(snapshot.Type),
		Name:        ruleSet.Name(),
		Format:      snapshot.Format,
		UpdatedAt:   snapshot.UpdatedAt,
		Revision:    snapshot.Revision,
		IPCIDR:      snapshot.IPCIDR,
	}
}

func ruleProviderVehicleType(providerType string) string {
	switch providerType {
	case C.RuleSetTypeRemote:
		return "HTTP"
	case C.RuleSetTypeLocal:
		return "File"
	default:
		return "Compatible"
	}
}

func serverRuleSets(server *Server) []adapter.RuleSet {
	if router, loaded := server.router.(interface{ RuleSets() []adapter.RuleSet }); loaded {
		return router.RuleSets()
	}
	return nil
}

func ruleProviderRevision(ruleSets []adapter.RuleSet) uint64 {
	var revision uint64
	for _, ruleSet := range ruleSets {
		if provider, loaded := ruleSet.(adapter.RuleSetProvider); loaded {
			revision += provider.ProviderSnapshot().Revision
		}
	}
	return revision
}

func watchRuleProviders(server *Server) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		ruleSets := serverRuleSets(server)
		events := make(chan ruleProviderEvent, max(1, len(ruleSets)))
		for _, ruleSet := range ruleSets {
			element := ruleSet.RegisterCallback(func(updated adapter.RuleSet) {
				event := ruleProviderEvent{Name: updated.Name(), Revision: ruleProviderRevision(ruleSets)}
				select {
				case events <- event:
				default:
				}
			})
			defer ruleSet.UnregisterCallback(element)
		}

		current := ruleProviderEvent{Revision: ruleProviderRevision(ruleSets)}
		if r.URL.Query().Get("once") == "1" {
			since, err := strconv.ParseUint(r.URL.Query().Get("since"), 10, 64)
			if err != nil && r.URL.Query().Get("since") != "" {
				render.Status(r, http.StatusBadRequest)
				render.JSON(w, r, ErrBadRequest)
				return
			}
			if current.Revision != since {
				render.JSON(w, r, current)
				return
			}
			select {
			case event := <-events:
				render.JSON(w, r, event)
			case <-r.Context().Done():
			}
			return
		}

		flusher, loaded := w.(http.Flusher)
		if !loaded {
			render.Status(r, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		if writeRuleProviderEvent(w, "snapshot", current) != nil {
			return
		}
		flusher.Flush()
		for {
			select {
			case event := <-events:
				if writeRuleProviderEvent(w, "update", event) != nil {
					return
				}
				flusher.Flush()
			case <-r.Context().Done():
				return
			}
		}
	}
}

func writeRuleProviderEvent(w http.ResponseWriter, eventType string, event ruleProviderEvent) error {
	content, err := json.Marshal(event)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", eventType, content)
	return err
}
