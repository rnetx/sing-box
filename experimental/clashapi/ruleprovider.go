package clashapi

import (
	"context"
	"net/http"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/badjson"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

func ruleProviderRouter(router adapter.Router) http.Handler {
	r := chi.NewRouter()
	r.Get("/", getRuleProviders(router))

	r.Route("/{name}", func(r chi.Router) {
		r.Use(parseProviderName, findRuleProviderByName(router))
		r.Get("/", getRuleProvider(router))
		r.Put("/", updateRuleProvider)
	})
	return r
}

func getRuleProviders(router adapter.Router) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		ruleProviders := router.RuleProviders()
		if ruleProviders == nil {
			render.Status(r, http.StatusOK)
			render.JSON(w, r, render.M{
				"providers": render.M{},
			})
			return
		}
		m := render.M{}
		for _, ruleProvider := range ruleProviders {
			m[ruleProvider.Tag()] = ruleProviderInfo(router, ruleProvider)
		}
		render.JSON(w, r, render.M{
			"providers": m,
		})
	}
}

func getRuleProvider(router adapter.Router) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		ruleProvider := r.Context().Value(CtxKeyProvider).(adapter.RuleProvider)
		render.JSON(w, r, ruleProviderInfo(router, ruleProvider))
		render.NoContent(w, r)
	}
}

func updateRuleProvider(w http.ResponseWriter, r *http.Request) {
	ruleProvider := r.Context().Value(CtxKeyProvider).(adapter.RuleProvider)
	ruleProvider.Update()
	render.NoContent(w, r)
}

func findRuleProviderByName(router adapter.Router) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			name := r.Context().Value(CtxKeyProviderName).(string)
			ruleProvider, loaded := router.RuleProvider(name)
			if !loaded {
				render.Status(r, http.StatusNotFound)
				render.JSON(w, r, ErrNotFound)
				return
			}

			ctx := context.WithValue(r.Context(), CtxKeyProvider, ruleProvider)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func ruleProviderInfo(router adapter.Router, ruleProvider adapter.RuleProvider) *badjson.JSONObject {
	var info badjson.JSONObject
	info.Put("name", ruleProvider.Tag())
	info.Put("type", "Rule")
	info.Put("vehicleType", "HTTP")
	info.Put("updatedAt", ruleProvider.LastUpdateTime())
	format, behavior, ruleCount, err := ruleProvider.GetRuleInfo()
	if err == nil {
		info.Put("format", format)
		info.Put("behavior", behavior)
		info.Put("ruleCount", ruleCount)
	}
	return &info
}
