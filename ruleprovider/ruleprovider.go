//go:build with_ruleprovider

package ruleprovider

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/simpledns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/rw"
)

var _ adapter.RuleProvider = (*RuleProvider)(nil)

type RuleProvider struct {
	ctx    context.Context
	router adapter.Router
	logger log.ContextLogger

	tag            string
	url            string
	useH3          bool
	format         Format
	behavior       Behavior
	cacheFile      string
	updateInterval time.Duration
	requestTimeout time.Duration
	dns            string
	requestDialer  N.Dialer
	runningDetour  string

	cacheLock            sync.RWMutex
	cache                *Cache
	autoUpdateCtx        context.Context
	autoUpdateCancel     context.CancelFunc
	autoUpdateCancelDone chan struct{}
	updateLock           sync.Mutex

	httpClient *http.Client
}

func NewRuleProvider(ctx context.Context, logger log.ContextLogger, tag string, options option.RuleProvider) (adapter.RuleProvider, error) {
	if tag == "" {
		return nil, E.New("tag is empty")
	}
	if options.Url == "" {
		return nil, E.New("url is empty")
	}
	r := &RuleProvider{
		ctx:    ctx,
		logger: logger,
		//
		tag:            tag,
		url:            options.Url,
		useH3:          options.UseH3,
		cacheFile:      options.CacheFile,
		dns:            options.DNS,
		runningDetour:  options.RunningDetour,
		updateInterval: time.Duration(options.UpdateInterval),
		requestTimeout: time.Duration(options.RequestTimeout),
	}
	switch options.Format {
	case string(FormatYAML), "":
		r.format = FormatYAML
	case string(FormatText):
		r.format = FormatText
	default:
		return nil, E.New("invalid format: ", options.Format)
	}
	switch options.Behavior {
	case string(BehaviorDomain):
		r.behavior = BehaviorDomain
	case string(BehaviorIPCIDR):
		r.behavior = BehaviorIPCIDR
	case string(BehaviorClassical):
		r.behavior = BehaviorClassical
	default:
		return nil, E.New("invalid behavior: ", options.Behavior)
	}
	if options.RequestDialer.Detour != "" {
		return nil, E.New("request dialer detour is not supported")
	}
	d, err := dialer.NewSimple(options.RequestDialer)
	if err != nil {
		return nil, E.Cause(err, "initialize request dialer failed")
	}
	r.requestDialer = d
	return r, nil
}

func (r *RuleProvider) Tag() string {
	return r.tag
}

func (r *RuleProvider) SetRouter(router adapter.Router) {
	r.router = router
}

func (r *RuleProvider) FormatRule(dnsRules *[]option.DNSRule, routeRules *[]option.Rule) ([]option.DNSRule, []option.Rule, error) {
	r.logger.Info("ruleprovider format rule")
	if r.cacheFile != "" {
		if rw.FileExists(r.cacheFile) {
			r.logger.Info("loading cache file: ", r.cacheFile)
			var cache Cache
			err := cache.ReadFromFile(r.cacheFile)
			if err != nil {
				return nil, nil, E.Cause(err, "invalid cache file")
			}
			if !cache.IsNil() {
				r.cache = new(Cache)
				*r.cache = cache
				r.logger.Info("cache file loaded")
			} else {
				r.logger.Info("cache file is empty")
			}
		}
	}
	if r.cache == nil || (r.cache != nil && r.updateInterval > 0 && r.cache.LastUpdate.Add(r.updateInterval).Before(time.Now())) {
		r.logger.Info("updating rule")
		cache, err := r.wrapUpdate(r.ctx, true)
		if err == nil {
			r.cache = cache
			if r.cacheFile != "" {
				r.logger.Info("writing cache file: ", r.cacheFile)
				err := cache.WriteToFile(r.cacheFile)
				if err != nil {
					return nil, nil, E.Cause(err, "write cache file failed")
				}
				r.logger.Info("write cache file done")
			}
			r.logger.Info("rule updated")
		}
		if err != nil {
			if r.cache == nil {
				return nil, nil, E.Cause(err, "update rule failed")
			} else {
				r.logger.Warn("update cache failed: ", err)
			}
		}
	}
	defer func() {
		r.cache.RuleSet = nil
	}()
	set := r.cache.RuleSet
	var newDNSRules []option.DNSRule
	if dnsRules != nil {
		for _, dnsRule := range *dnsRules {
			if dnsRule.DefaultOptions.RuleProvider != r.tag {
				newDNSRules = append(newDNSRules, dnsRule)
				continue
			}
			dnsRule.DefaultOptions.RuleProvider = ""
			ruleProviderRules, err := set.AppendDNSRuleToOptions(&dnsRule)
			if err != nil {
				return nil, nil, E.Cause(err, "append dns rule failed")
			}
			newDNSRules = append(newDNSRules, ruleProviderRules...)
		}
	}
	var newRouteRules []option.Rule
	if routeRules != nil {
		for _, routeRule := range *routeRules {
			if routeRule.DefaultOptions.RuleProvider != r.tag {
				newRouteRules = append(newRouteRules, routeRule)
				continue
			}
			routeRule.DefaultOptions.RuleProvider = ""
			ruleProviderRules, err := set.AppendRouteRuleToOptions(&routeRule)
			if err != nil {
				return nil, nil, E.Cause(err, "append route rule failed")
			}
			newRouteRules = append(newRouteRules, ruleProviderRules...)
		}
	}
	return newDNSRules, newRouteRules, nil
}

func (r *RuleProvider) Start() error {
	if r.updateInterval > 0 && r.cacheFile != "" {
		r.autoUpdateCtx, r.autoUpdateCancel = context.WithCancel(r.ctx)
		r.autoUpdateCancelDone = make(chan struct{}, 1)
		go r.loopUpdate()
	}
	return nil
}

func (r *RuleProvider) loopUpdate() {
	defer func() {
		r.autoUpdateCancelDone <- struct{}{}
	}()
	ticker := time.NewTicker(r.updateInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			r.update(r.autoUpdateCtx, false)
		case <-r.autoUpdateCtx.Done():
			return
		}
	}
}

func (r *RuleProvider) Close() error {
	if r.autoUpdateCtx != nil {
		r.autoUpdateCancel()
		<-r.autoUpdateCancelDone
	}
	return nil
}

func (r *RuleProvider) Update() {
	if r.updateInterval > 0 && r.cacheFile != "" {
		r.update(r.ctx, false)
	}
}

func (r *RuleProvider) update(ctx context.Context, isFirst bool) {
	if !r.updateLock.TryLock() {
		return
	}
	defer r.updateLock.Unlock()

	r.logger.Info("updating cache")
	cache, err := r.wrapUpdate(ctx, false)
	if err != nil {
		r.logger.Error("update cache failed: ", err)
		return
	}
	r.logger.Info("cache updated")
	r.cacheLock.Lock()
	r.cache = cache
	if r.cacheFile != "" {
		err = cache.WriteToFile(r.cacheFile)
		if err != nil {
			r.logger.Error("write cache file failed: ", err)
			return
		}
	}
	r.cache.RuleSet = nil
	r.cacheLock.Unlock()
}

func (r *RuleProvider) wrapUpdate(ctx context.Context, isFirst bool) (*Cache, error) {
	var httpClient *http.Client
	if isFirst {
		if !r.useH3 {
			httpClient = &http.Client{
				Transport: &http.Transport{
					DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
						if r.dns != "" {
							host, _, err := net.SplitHostPort(addr)
							if err != nil {
								return nil, err
							}
							ips, err := simpledns.DNSLookup(ctx, r.requestDialer, r.dns, host, true, true)
							if err != nil {
								return nil, err
							}
							return N.DialParallel(ctx, r.requestDialer, network, M.ParseSocksaddr(addr), ips, false, 5*time.Second)
						} else {
							return r.requestDialer.DialContext(ctx, network, M.ParseSocksaddr(addr))
						}
					},
					ForceAttemptHTTP2: true,
				},
			}
		} else {
			httpClient = &http.Client{
				Transport: &http3.RoundTripper{
					Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
						var conn net.Conn
						var err error
						if r.dns != "" {
							host, _, err := net.SplitHostPort(addr)
							if err != nil {
								return nil, err
							}
							ips, err := simpledns.DNSLookup(ctx, r.requestDialer, r.dns, host, true, true)
							if err != nil {
								return nil, err
							}
							conn, err = N.DialParallel(ctx, r.requestDialer, N.NetworkUDP, M.ParseSocksaddr(addr), ips, false, 5*time.Second)
						} else {
							conn, err = r.requestDialer.DialContext(ctx, N.NetworkUDP, M.ParseSocksaddr(addr))
						}
						if err != nil {
							return nil, err
						}
						return quic.DialEarly(ctx, bufio.NewUnbindPacketConn(conn), conn.RemoteAddr(), tlsCfg, cfg)
					},
				},
			}
		}
	} else if r.httpClient == nil {
		if !r.useH3 {
			httpClient = &http.Client{
				Transport: &http.Transport{
					DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
						dialer := r.requestDialer
						if r.runningDetour != "" {
							var loaded bool
							dialer, loaded = r.router.Outbound(r.runningDetour)
							if !loaded {
								return nil, E.New("running detour not found")
							}
						}
						if r.dns != "" {
							host, _, err := net.SplitHostPort(addr)
							if err != nil {
								return nil, err
							}
							ips, err := simpledns.DNSLookup(ctx, dialer, r.dns, host, true, true)
							if err != nil {
								return nil, err
							}
							return N.DialParallel(ctx, dialer, network, M.ParseSocksaddr(addr), ips, false, 5*time.Second)
						} else {
							return dialer.DialContext(ctx, network, M.ParseSocksaddr(addr))
						}
					},
					ForceAttemptHTTP2: true,
				},
			}
		} else {
			httpClient = &http.Client{
				Transport: &http3.RoundTripper{
					Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
						var conn net.Conn
						var err error
						dialer := r.requestDialer
						if r.runningDetour != "" {
							var loaded bool
							dialer, loaded = r.router.Outbound(r.runningDetour)
							if !loaded {
								return nil, E.New("running detour not found")
							}
						}
						if r.dns != "" {
							host, _, err := net.SplitHostPort(addr)
							if err != nil {
								return nil, err
							}
							ips, err := simpledns.DNSLookup(ctx, dialer, r.dns, host, true, true)
							if err != nil {
								return nil, err
							}
							conn, err = N.DialParallel(ctx, dialer, N.NetworkUDP, M.ParseSocksaddr(addr), ips, false, 5*time.Second)
						} else {
							conn, err = dialer.DialContext(ctx, N.NetworkUDP, M.ParseSocksaddr(addr))
						}
						if err != nil {
							return nil, err
						}
						return quic.DialEarly(ctx, bufio.NewUnbindPacketConn(conn), conn.RemoteAddr(), tlsCfg, cfg)
					},
				},
			}
		}
		r.httpClient = httpClient
	} else {
		httpClient = r.httpClient
	}
	if r.requestTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.requestTimeout)
		defer cancel()
	}
	return request(ctx, r.logger, httpClient, r.format, r.behavior, r.url)
}

func (r *RuleProvider) LastUpdateTime() time.Time {
	r.cacheLock.RLock()
	defer r.cacheLock.RUnlock()
	if r.cache != nil {
		return r.cache.LastUpdate
	}
	return time.Time{}
}

func (r *RuleProvider) GetRuleInfo() (format string, behavior string, ruleCount uint64, err error) {
	r.cacheLock.RLock()
	defer r.cacheLock.RUnlock()
	if r.cache != nil {
		format = r.cache.Format
		behavior = r.cache.Behavior
		ruleCount = r.cache.RuleCount
	}
	return
}
