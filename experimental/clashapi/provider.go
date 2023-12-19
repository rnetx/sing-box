package clashapi

import (
	"context"
	"net/http"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/json/badjson"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

func proxyProviderRouter(server *Server, router adapter.Router) http.Handler {
	r := chi.NewRouter()
	r.Get("/", getProviders(server, router))

	r.Route("/{name}", func(r chi.Router) {
		r.Use(parseProviderName, findProviderByName(router))
		r.Get("/", getProvider(server, router))
		r.Put("/", updateProvider)
		r.Get("/healthcheck", healthCheckProvider)
	})
	return r
}

func getProviders(server *Server, router adapter.Router) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		providers := router.ProviderOutbounds()
		if len(providers) == 0 {
			render.JSON(w, r, render.M{
				"providers": render.M{},
			})
		}
		m := render.M{}
		for _, provider := range providers {
			m[provider.Tag()] = proxyProviderInfo(server, router, provider)
		}
		render.JSON(w, r, render.M{
			"providers": m,
		})
	}
}

func getProvider(server *Server, router adapter.Router) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		provider := r.Context().Value(CtxKeyProvider).(adapter.ProviderOutbound)
		render.JSON(w, r, proxyProviderInfo(server, router, provider))
	}
}

func updateProvider(w http.ResponseWriter, r *http.Request) {
	provider := r.Context().Value(CtxKeyProvider).(adapter.ProviderOutbound)
	provider.CallUpdate()
	render.NoContent(w, r)
}

func healthCheckProvider(w http.ResponseWriter, r *http.Request) {
	provider := r.Context().Value(CtxKeyProvider).(adapter.ProviderOutbound)
	provider.HealthCheck(r.Context(), "")
	render.NoContent(w, r)
}

func parseProviderName(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := getEscapeParam(r, "name")
		ctx := context.WithValue(r.Context(), CtxKeyProviderName, name)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func findProviderByName(router adapter.Router) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			name := r.Context().Value(CtxKeyProviderName).(string)
			provider, exist := router.ProviderOutbound(name)
			if !exist {
				render.Status(r, http.StatusNotFound)
				render.JSON(w, r, ErrNotFound)
				return
			}

			ctx := context.WithValue(r.Context(), CtxKeyProvider, provider)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func proxyProviderInfo(server *Server, router adapter.Router, proxyProvider adapter.ProviderOutbound) *badjson.JSONObject {
	var info badjson.JSONObject
	info.Put("name", proxyProvider.Tag())
	info.Put("type", "Proxy")
	info.Put("vehicleType", "HTTP")
	subscriptionInfo := render.M{}
	providerInfo := proxyProvider.ProviderInfo()
	subscriptionInfo["Download"] = providerInfo.Download
	subscriptionInfo["Upload"] = providerInfo.Upload
	subscriptionInfo["Total"] = providerInfo.Total
	subscriptionInfo["Expire"] = providerInfo.ExpireTime.Unix()
	info.Put("subscriptionInfo", subscriptionInfo)
	info.Put("updatedAt", providerInfo.UpdateTime)
	outbounds := proxyProvider.Outbounds()
	proxies := make([]*badjson.JSONObject, 0)
	for _, outbound := range outbounds {
		switch outbound.Type() {
		case C.TypeSelector, C.TypeURLTest:
		default:
			proxies = append(proxies, proxyInfo(server, outbound))
		}
	}
	info.Put("proxies", proxies)
	return &info
}
