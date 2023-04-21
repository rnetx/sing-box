package clashapi

import (
	"context"
	"encoding/json"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/badjson"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"net/http"
	"sync"
	"time"
)

func proxyProviderRouter(server *Server, router adapter.Router) http.Handler {
	r := chi.NewRouter()
	r.Get("/", getProviders(server, router))

	r.Route("/{name}", func(r chi.Router) {
		r.Use(parseProviderName, findProviderByName(router))
		r.Get("/", getProvider(server, router))
		r.Put("/", updateProvider)
		r.Get("/healthcheck", healthCheckProvider(router))
	})
	return r
}

func getProviders(server *Server, router adapter.Router) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var proxyMap badjson.JSONObject
		pps := router.ListProxyProvider()
		if pps == nil {
			render.NoContent(w, r)
			return
		}
		for _, v := range router.ListProxyProvider() {
			proxyMap.Put(v.Tag(), proxyProviderInfo(server, router, v))
		}
		render.JSON(w, r, render.M{
			"providers": proxyMap,
		})
	}
}

func getProvider(server *Server, router adapter.Router) func(w http.ResponseWriter, r *http.Request) {
	/*provider := r.Context().Value(CtxKeyProvider).(provider.ProxyProvider)
	render.JSON(w, r, provider)*/
	//render.NoContent(w, r)
	return func(w http.ResponseWriter, r *http.Request) {
		proxyProvider := r.Context().Value(CtxKeyProxy).(adapter.ProxyProvider)
		response, err := json.Marshal(proxyProviderInfo(server, router, proxyProvider))
		if err != nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		w.Write(response)
	}
}

func updateProvider(w http.ResponseWriter, r *http.Request) {
	proxyProvider := r.Context().Value(CtxKeyProvider).(adapter.ProxyProvider)
	if err := proxyProvider.ForceUpdate(); err != nil {
		render.Status(r, http.StatusServiceUnavailable)
		render.JSON(w, r, newError(err.Error()))
		return
	}
	render.NoContent(w, r)
}

func healthCheckProvider(router adapter.Router) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		proxyProvider := r.Context().Value(CtxKeyProvider).(adapter.ProxyProvider)
		//provider.HealthCheck()
		outs := router.GetProxyProviderOutbound(proxyProvider.Tag())
		if outs == nil {
			render.NoContent(w, r)
		}

		wg := sync.WaitGroup{}
		for _, out := range outs {
			wg.Add(1)
			go func(out adapter.Outbound) {
				defer wg.Done()
				ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
				defer cancel()
				urltest.URLTest(ctx, "", out)
			}(out)
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
			proxyProvider := router.GetProxyProvider(name)
			if proxyProvider == nil {
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
	info.Put("subscriptionInfo", map[string]any{
		"Upload":   proxyProvider.GetSubscribeInfo().GetUpload(),
		"Download": proxyProvider.GetSubscribeInfo().GetDownload(),
		"Total":    proxyProvider.GetSubscribeInfo().GetTotal(),
		"Expire":   uint64(proxyProvider.GetSubscribeInfo().GetExpire().Unix()),
	})
	info.Put("updatedAt", proxyProvider.GetUpdateTime().Format("2006-01-02T15:04:05.999999999-07:00"))
	proxys := make([]*badjson.JSONObject, 0)
	outs := router.GetProxyProviderOutbound(proxyProvider.Tag())
	if outs != nil {
		for _, out := range outs {
			switch out.Type() {
			case C.TypeSelector, C.TypeURLTest:
				continue
			}
			proxys = append(proxys, proxyInfo(server, out))
		}
	}
	info.Put("proxies", proxys)
	return &info
}
