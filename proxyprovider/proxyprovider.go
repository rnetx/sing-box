//go:build with_proxyprovider

package proxyprovider

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/simpledns"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/rw"
)

var _ adapter.ProxyProvider = (*ProxyProvider)(nil)

type ProxyProvider struct {
	ctx    context.Context
	router adapter.Router
	logger log.ContextLogger
	tag    string

	url            string
	cacheFile      string
	updateInterval time.Duration
	requestTimeout time.Duration
	dns            string
	tagFormat      string
	globalFilter   *Filter
	groups         []Group
	dialer         *option.DialerOptions
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

func NewProxyProvider(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.ProxyProvider) (adapter.ProxyProvider, error) {
	if tag == "" {
		return nil, E.New("tag is empty")
	}
	if options.Url == "" {
		return nil, E.New("url is empty")
	}
	var globalFilter *Filter
	if options.GlobalFilter != nil {
		var err error
		globalFilter, err = NewFilter(options.GlobalFilter)
		if err != nil {
			return nil, E.Cause(err, "initialize global filter failed")
		}
	}
	p := &ProxyProvider{
		ctx:    ctx,
		router: router,
		logger: logger,
		//
		tag:            tag,
		url:            options.Url,
		cacheFile:      options.CacheFile,
		dns:            options.DNS,
		dialer:         options.Dialer,
		runningDetour:  options.RunningDetour,
		tagFormat:      options.TagFormat,
		updateInterval: time.Duration(options.UpdateInterval),
		requestTimeout: time.Duration(options.RequestTimeout),
		globalFilter:   globalFilter,
	}
	if options.Groups != nil && len(options.Groups) > 0 {
		groups := make([]Group, 0, len(options.Groups))
		for _, groupOptions := range options.Groups {
			g := Group{
				Tag:             groupOptions.Tag,
				Type:            groupOptions.Type,
				SelectorOptions: groupOptions.SelectorOptions,
				URLTestOptions:  groupOptions.URLTestOptions,
			}
			if groupOptions.Filter != nil {
				filter, err := NewFilter(groupOptions.Filter)
				if err != nil {
					return nil, E.Cause(err, "initialize group filter failed")
				}
				g.Filter = filter
			}
			groups = append(groups, g)
		}
		p.groups = groups
	}
	if options.RequestDialer.Detour != "" {
		return nil, E.New("request dialer detour is not supported")
	}
	d, err := dialer.NewSimple(options.RequestDialer)
	if err != nil {
		return nil, E.Cause(err, "initialize request dialer failed")
	}
	p.requestDialer = d
	return p, nil
}

func (p *ProxyProvider) Tag() string {
	return p.tag
}

func (p *ProxyProvider) StartGetOutbounds() ([]option.Outbound, error) {
	p.logger.Info("proxyprovider get outbounds")
	if p.cacheFile != "" {
		if rw.FileExists(p.cacheFile) {
			p.logger.Info("loading cache file: ", p.cacheFile)
			var cache Cache
			err := cache.ReadFromFile(p.cacheFile)
			if err != nil {
				return nil, E.Cause(err, "invalid cache file")
			}
			if !cache.IsNil() {
				p.cache = new(Cache)
				*p.cache = cache
				p.logger.Info("cache file loaded")
			} else {
				p.logger.Info("cache file is empty")
			}
		}
	}
	if p.cache == nil || (p.cache != nil && p.updateInterval > 0 && p.cache.LastUpdate.Add(p.updateInterval).Before(time.Now())) {
		p.logger.Info("updating outbounds")
		cache, err := p.wrapUpdate(p.ctx, true)
		if err == nil {
			p.cache = cache
			if p.cacheFile != "" {
				p.logger.Info("writing cache file: ", p.cacheFile)
				err := cache.WriteToFile(p.cacheFile)
				if err != nil {
					return nil, E.Cause(err, "write cache file failed")
				}
				p.logger.Info("write cache file done")
			}
			p.logger.Info("outbounds updated")
		}
		if err != nil {
			if p.cache == nil {
				return nil, E.Cause(err, "update outbounds failed")
			} else {
				p.logger.Warn("update cache failed: ", err)
			}
		}
	}
	defer func() {
		p.cache.Outbounds = nil
	}()
	return p.GetFullOutboundOptions()
}

func (p *ProxyProvider) Start() error {
	if p.updateInterval > 0 && p.cacheFile != "" {
		p.autoUpdateCtx, p.autoUpdateCancel = context.WithCancel(p.ctx)
		p.autoUpdateCancelDone = make(chan struct{}, 1)
		go p.loopUpdate()
	}
	return nil
}

func (p *ProxyProvider) loopUpdate() {
	defer func() {
		p.autoUpdateCancelDone <- struct{}{}
	}()
	ticker := time.NewTicker(p.updateInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			p.update(p.autoUpdateCtx, false)
		case <-p.autoUpdateCtx.Done():
			return
		}
	}
}

func (p *ProxyProvider) Close() error {
	if p.autoUpdateCtx != nil {
		p.autoUpdateCancel()
		<-p.autoUpdateCancelDone
	}
	return nil
}

func (p *ProxyProvider) GetOutboundOptions() ([]option.Outbound, error) {
	p.cacheLock.RLock()
	defer p.cacheLock.RUnlock()
	return p.cache.Outbounds, nil
}

func (p *ProxyProvider) GetFullOutboundOptions() ([]option.Outbound, error) {
	p.cacheLock.RLock()
	outbounds := p.cache.Outbounds
	p.cacheLock.RUnlock()

	if p.dialer != nil {
		for i := range outbounds {
			outbound := &outbounds[i]
			setDialerOptions(outbound, p.dialer)
		}
	}

	var outboundTagMap map[string]string
	finalOutbounds := make([]option.Outbound, 0, len(outbounds))
	finalOutbounds = append(finalOutbounds, outbounds...)

	if p.tagFormat != "" {
		outboundTagMap = make(map[string]string, len(outbounds))
		for i := range finalOutbounds {
			tag := finalOutbounds[i].Tag
			finalTag := fmt.Sprintf(p.tagFormat, tag)
			outboundTagMap[finalTag] = tag
			finalOutbounds[i].Tag = finalTag
		}
	}

	var allOutboundTags []string
	for _, outbound := range finalOutbounds {
		allOutboundTags = append(allOutboundTags, outbound.Tag)
	}

	var groupOutbounds []option.Outbound
	var groupOutboundTags []string
	if p.groups != nil && len(p.groups) > 0 {
		groupOutbounds = make([]option.Outbound, 0, len(p.groups))
		for _, group := range p.groups {
			var outboundTags []string
			if group.Filter != nil {
				outboundTags = group.Filter.Filter(allOutboundTags)
			} else {
				outboundTags = allOutboundTags
			}
			if len(outboundTags) == 0 {
				return nil, E.New("no outbound available for group: ", group.Tag)
			}
			outboundOptions := option.Outbound{
				Tag:             group.Tag,
				Type:            group.Type,
				SelectorOptions: group.SelectorOptions,
				URLTestOptions:  group.URLTestOptions,
			}
			var outbounds []string
			switch group.Type {
			case C.TypeSelector:
				outbounds = append(outbounds, group.SelectorOptions.Outbounds...)
				outbounds = append(outbounds, outboundTags...)
				outboundOptions.SelectorOptions.Outbounds = outbounds
			case C.TypeURLTest:
				outbounds = append(outbounds, group.URLTestOptions.Outbounds...)
				outbounds = append(outbounds, outboundTags...)
				outboundOptions.URLTestOptions.Outbounds = outbounds
			}
			groupOutbounds = append(groupOutbounds, outboundOptions)
			groupOutboundTags = append(groupOutboundTags, group.Tag)
		}
	}

	globalOutbound := option.Outbound{
		Tag:  p.tag,
		Type: C.TypeSelector,
		SelectorOptions: option.SelectorOutboundOptions{
			Outbounds: allOutboundTags,
		},
	}
	if len(groupOutboundTags) > 0 {
		finalOutbounds = append(finalOutbounds, groupOutbounds...)
		globalOutbound.SelectorOptions.Outbounds = append(globalOutbound.SelectorOptions.Outbounds, groupOutboundTags...)
	}

	finalOutbounds = append(finalOutbounds, globalOutbound)

	return finalOutbounds, nil
}

func (p *ProxyProvider) GetClashInfo() (download uint64, upload uint64, total uint64, expire time.Time, err error) {
	p.cacheLock.RLock()
	defer p.cacheLock.RUnlock()
	if p.cache.ClashInfo != nil {
		download = p.cache.ClashInfo.Download
		upload = p.cache.ClashInfo.Upload
		total = p.cache.ClashInfo.Total
		expire = p.cache.ClashInfo.Expire
	}
	return
}

func (p *ProxyProvider) Update() {
	if p.updateInterval > 0 && p.cacheFile != "" {
		p.update(p.ctx, false)
	}
}

func (p *ProxyProvider) update(ctx context.Context, isFirst bool) {
	if !p.updateLock.TryLock() {
		return
	}
	defer p.updateLock.Unlock()

	p.logger.Info("updating cache")
	cache, err := p.wrapUpdate(ctx, false)
	if err != nil {
		p.logger.Error("update cache failed: ", err)
		return
	}
	p.cacheLock.Lock()
	p.cache = cache
	if p.cacheFile != "" {
		err = cache.WriteToFile(p.cacheFile)
		if err != nil {
			p.logger.Error("write cache file failed: ", err)
			return
		}
	}
	p.cache.Outbounds = nil
	p.cacheLock.Unlock()
}

func (p *ProxyProvider) wrapUpdate(ctx context.Context, isFirst bool) (*Cache, error) {
	var httpClient *http.Client
	if isFirst {
		httpClient = &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					if p.dns != "" {
						host, _, err := net.SplitHostPort(addr)
						if err != nil {
							return nil, err
						}
						ips, err := simpledns.DNSLookup(ctx, p.requestDialer, p.dns, host, true, true)
						if err != nil {
							return nil, err
						}
						return N.DialParallel(ctx, p.requestDialer, network, M.ParseSocksaddr(addr), ips, false, 5*time.Second)
					} else {
						return p.requestDialer.DialContext(ctx, network, M.ParseSocksaddr(addr))
					}
				},
				ForceAttemptHTTP2: true,
			},
		}
	} else if p.httpClient == nil {
		httpClient = &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					dialer := p.requestDialer
					if p.runningDetour != "" {
						var loaded bool
						dialer, loaded = p.router.Outbound(p.runningDetour)
						if !loaded {
							return nil, E.New("running detour not found")
						}
					}
					if p.dns != "" {
						host, _, err := net.SplitHostPort(addr)
						if err != nil {
							return nil, err
						}
						ips, err := simpledns.DNSLookup(ctx, dialer, p.dns, host, true, true)
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
		p.httpClient = httpClient
	} else {
		httpClient = p.httpClient
	}
	if p.requestTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, p.requestTimeout)
		defer cancel()
	}
	cache, err := request(ctx, httpClient, p.url)
	if err != nil {
		return nil, err
	}
	if p.globalFilter != nil {
		outboundTagMap := make(map[string]*option.Outbound)
		outboundTags := make([]string, 0, len(cache.Outbounds))
		for i := range cache.Outbounds {
			outboundTagMap[cache.Outbounds[i].Tag] = &cache.Outbounds[i]
			outboundTags = append(outboundTags, cache.Outbounds[i].Tag)
		}
		newOutboundTags := p.globalFilter.Filter(outboundTags)
		if len(newOutboundTags) == 0 {
			return nil, E.New("no outbound available")
		}
		newOutbounds := make([]option.Outbound, 0, len(newOutboundTags))
		for i := range newOutboundTags {
			newOutbounds = append(newOutbounds, *outboundTagMap[newOutboundTags[i]])
		}
		cache.Outbounds = newOutbounds
	}
	return cache, nil
}

func (p *ProxyProvider) LastUpdateTime() time.Time {
	p.cacheLock.RLock()
	defer p.cacheLock.RUnlock()
	if p.cache != nil {
		return p.cache.LastUpdate
	}
	return time.Time{}
}

func setDialerOptions(outbound *option.Outbound, dialer *option.DialerOptions) {
	newDialer := copyDialerOptions(dialer)
	switch outbound.Type {
	case C.TypeDirect:
		mergeDialerOptions(&outbound.DirectOptions.DialerOptions, &newDialer)
	case C.TypeHTTP:
		mergeDialerOptions(&outbound.HTTPOptions.DialerOptions, &newDialer)
	case C.TypeShadowsocks:
		mergeDialerOptions(&outbound.ShadowsocksOptions.DialerOptions, &newDialer)
	case C.TypeVMess:
		mergeDialerOptions(&outbound.VMessOptions.DialerOptions, &newDialer)
	case C.TypeTrojan:
		mergeDialerOptions(&outbound.TrojanOptions.DialerOptions, &newDialer)
	case C.TypeWireGuard:
		mergeDialerOptions(&outbound.WireGuardOptions.DialerOptions, &newDialer)
	case C.TypeHysteria:
		mergeDialerOptions(&outbound.HysteriaOptions.DialerOptions, &newDialer)
	case C.TypeTor:
		mergeDialerOptions(&outbound.TorOptions.DialerOptions, &newDialer)
	case C.TypeSSH:
		mergeDialerOptions(&outbound.SSHOptions.DialerOptions, &newDialer)
	case C.TypeShadowTLS:
		mergeDialerOptions(&outbound.ShadowTLSOptions.DialerOptions, &newDialer)
	case C.TypeShadowsocksR:
		mergeDialerOptions(&outbound.ShadowsocksROptions.DialerOptions, &newDialer)
	case C.TypeVLESS:
		mergeDialerOptions(&outbound.VLESSOptions.DialerOptions, &newDialer)
	case C.TypeTUIC:
		mergeDialerOptions(&outbound.TUICOptions.DialerOptions, &newDialer)
	case C.TypeHysteria2:
		mergeDialerOptions(&outbound.Hysteria2Options.DialerOptions, &newDialer)
	case C.TypeRandomAddr:
		mergeDialerOptions(&outbound.RandomAddrOptions.DialerOptions, &newDialer)
	}
}

func copyDialerOptions(dialer *option.DialerOptions) option.DialerOptions {
	newDialer := option.DialerOptions{
		Detour:             dialer.Detour,
		BindInterface:      dialer.BindInterface,
		ProtectPath:        dialer.ProtectPath,
		RoutingMark:        dialer.RoutingMark,
		ReuseAddr:          dialer.ReuseAddr,
		ConnectTimeout:     dialer.ConnectTimeout,
		TCPFastOpen:        dialer.TCPFastOpen,
		TCPMultiPath:       dialer.TCPMultiPath,
		UDPFragmentDefault: dialer.UDPFragmentDefault,
		DomainStrategy:     dialer.DomainStrategy,
		FallbackDelay:      dialer.FallbackDelay,
	}
	if dialer.Inet4BindAddress != nil {
		newDialer.Inet4BindAddress = new(option.ListenAddress)
		*newDialer.Inet4BindAddress = *dialer.Inet4BindAddress
	}
	if dialer.Inet6BindAddress != nil {
		newDialer.Inet6BindAddress = new(option.ListenAddress)
		*newDialer.Inet6BindAddress = *dialer.Inet6BindAddress
	}
	if dialer.UDPFragment != nil {
		newDialer.UDPFragment = new(bool)
		*newDialer.UDPFragment = *dialer.UDPFragment
	}
	return newDialer
}

func mergeDialerOptions(old, new *option.DialerOptions) {
	if old == nil || new == nil {
		return
	}
	if new.Detour != "" {
		old.Detour = new.Detour
	}
	if new.BindInterface != "" {
		old.BindInterface = new.BindInterface
	}
	if new.Inet4BindAddress != nil {
		old.Inet4BindAddress = new.Inet4BindAddress
	}
	if new.Inet6BindAddress != nil {
		old.Inet6BindAddress = new.Inet6BindAddress
	}
	if new.ProtectPath != "" {
		old.ProtectPath = new.ProtectPath
	}
	if new.RoutingMark != 0 {
		old.RoutingMark = new.RoutingMark
	}
	if new.ReuseAddr {
		old.ReuseAddr = new.ReuseAddr
	}
	if new.ConnectTimeout > 0 {
		old.ConnectTimeout = new.ConnectTimeout
	}
	if new.TCPFastOpen {
		old.TCPFastOpen = new.TCPFastOpen
	}
	if new.TCPMultiPath {
		old.TCPMultiPath = new.TCPMultiPath
	}
	if new.UDPFragment != nil {
		old.UDPFragment = new.UDPFragment
	}
	if new.DomainStrategy != 0 {
		old.DomainStrategy = new.DomainStrategy
	}
	if new.FallbackDelay > 0 {
		old.FallbackDelay = new.FallbackDelay
	}
}
