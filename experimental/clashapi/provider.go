package clashapi

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/badjson"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/outbound"

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
		r.Get("/healthcheck", healthCheckProvider(server, router))
	})
	return r
}

func getProviders(server *Server, router adapter.Router) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		proxyProviders := router.ProxyProviders()
		if proxyProviders == nil {
			render.Status(r, http.StatusOK)
			render.JSON(w, r, render.M{
				"providers": render.M{},
			})
			return
		}
		m := render.M{}
		for _, proxyProvider := range proxyProviders {
			m[proxyProvider.Tag()] = proxyProviderInfo(server, router, proxyProvider)
		}
		render.JSON(w, r, render.M{
			"providers": m,
		})
	}
}

func getProvider(server *Server, router adapter.Router) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		proxyProvider := r.Context().Value(CtxKeyProvider).(adapter.ProxyProvider)
		render.JSON(w, r, proxyProviderInfo(server, router, proxyProvider))
		render.NoContent(w, r)
	}
}

func updateProvider(w http.ResponseWriter, r *http.Request) {
	proxyProvider := r.Context().Value(CtxKeyProvider).(adapter.ProxyProvider)
	proxyProvider.Update()
	render.NoContent(w, r)
}

func healthCheckProvider(server *Server, router adapter.Router) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		proxyProvider := r.Context().Value(CtxKeyProvider).(adapter.ProxyProvider)
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()

		wg := &sync.WaitGroup{}

		proxyProviderOutbound, loaded := router.Outbound(proxyProvider.Tag())
		if loaded {
			proxyProviderGroupOutbound := proxyProviderOutbound.(adapter.OutboundGroup)
			for _, outboundTag := range proxyProviderGroupOutbound.All() {
				out, loaded := router.Outbound(outboundTag)
				if loaded {
					wg.Add(1)
					go func(proxy adapter.Outbound) {
						defer wg.Done()
						delay, err := urltest.URLTest(ctx, "", proxy)
						defer func() {
							realTag := outbound.RealTag(proxy)
							if err != nil {
								server.urlTestHistory.DeleteURLTestHistory(realTag)
							} else {
								server.urlTestHistory.StoreURLTestHistory(realTag, &urltest.History{
									Time:  time.Now(),
									Delay: delay,
								})
							}
						}()
					}(out)
				}
			}
		}

		wg.Wait()

		render.NoContent(w, r)
	}
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
			proxyProvider, loaded := router.ProxyProvider(name)
			if !loaded {
				render.Status(r, http.StatusNotFound)
				render.JSON(w, r, ErrNotFound)
				return
			}

			ctx := context.WithValue(r.Context(), CtxKeyProvider, proxyProvider)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func proxyProviderInfo(server *Server, router adapter.Router, proxyProvider adapter.ProxyProvider) *badjson.JSONObject {
	var info badjson.JSONObject
	info.Put("name", proxyProvider.Tag())
	info.Put("type", "Proxy")
	info.Put("vehicleType", "HTTP")
	subscriptionInfo := render.M{}
	download, upload, total, expire, err := proxyProvider.GetClashInfo()
	if err == nil {
		subscriptionInfo["Download"] = download
		subscriptionInfo["Upload"] = upload
		subscriptionInfo["Total"] = total
		subscriptionInfo["Expire"] = expire.Unix()
	} else {
		subscriptionInfo["Download"] = 0
		subscriptionInfo["Upload"] = 0
		subscriptionInfo["Total"] = 0
		subscriptionInfo["Expire"] = 0
	}
	info.Put("subscriptionInfo", subscriptionInfo)
	info.Put("updatedAt", proxyProvider.LastUpdateTime())
	proxyProviderOutbound, loaded := router.Outbound(proxyProvider.Tag())
	if loaded {
		proxies := make([]*badjson.JSONObject, 0)
		proxyProviderGroupOutbound := proxyProviderOutbound.(adapter.OutboundGroup)
		for _, outboundTag := range proxyProviderGroupOutbound.All() {
			out, loaded := router.Outbound(outboundTag)
			if loaded {
				switch out.Type() {
				case C.TypeSelector, C.TypeURLTest:
					continue
				}
				proxies = append(proxies, proxyInfo(server, out))
			}
		}
		info.Put("proxies", proxies)
	}
	return &info
}
