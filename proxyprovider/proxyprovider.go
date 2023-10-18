//go:build with_proxyprovider

package proxyprovider

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/simpledns"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/proxyprovider/clash"
	"github.com/sagernet/sing-box/proxyprovider/raw"
	"github.com/sagernet/sing-box/proxyprovider/singbox"
	"github.com/sagernet/sing/common/bufio"
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
	ua             string
	useH3          bool
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
	lookupIP       bool

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
	if options.UserAgent == "" {
		options.UserAgent = "clash.meta; sing-box"
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
		ua:             options.UserAgent,
		useH3:          options.UseH3,
		cacheFile:      options.CacheFile,
		dns:            options.DNS,
		dialer:         options.Dialer,
		runningDetour:  options.RunningDetour,
		lookupIP:       options.LookupIP,
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
				JSTestOptions:   groupOptions.JSTestOptions,
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
	return p.getFullOutboundOptions(p.ctx)
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
	return p.getFullOutboundOptions(p.ctx)
}

func (p *ProxyProvider) getFullOutboundOptions(ctx context.Context) ([]option.Outbound, error) {
	p.cacheLock.RLock()
	outbounds := p.cache.Outbounds
	p.cacheLock.RUnlock()

	if p.dialer != nil {
		for i := range outbounds {
			outbound := &outbounds[i]
			setDialerOptions(outbound, p.dialer)
		}
	}

	if p.lookupIP && p.dns != "" {
		for i := range outbounds {
			outbound := &outbounds[i]
			ips, err := simpledns.DNSLookup(ctx, p.requestDialer, p.dns, getServer(outbound), true, true)
			if err != nil {
				return nil, err
			}
			setServer(outbound, ips[0].String())
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

	outboundOptionsMap := make(map[string]*option.Outbound)
	for i := range finalOutbounds {
		outbound := &finalOutbounds[i]
		outboundOptionsMap[outbound.Tag] = outbound
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
				groupOutbounds := group.Filter.Filter(finalOutbounds, outboundTagMap)
				for _, outbound := range groupOutbounds {
					outboundTags = append(outboundTags, outbound.Tag)
				}
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
				JSTestOptions:   group.JSTestOptions,
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
			case C.TypeJSTest:
				outbounds = append(outbounds, group.JSTestOptions.Outbounds...)
				outbounds = append(outbounds, outboundTags...)
				outboundOptions.JSTestOptions.Outbounds = outbounds
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
		if !p.useH3 {
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
		} else {
			httpClient = &http.Client{
				Transport: &http3.RoundTripper{
					Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
						var conn net.Conn
						var err error
						if p.dns != "" {
							host, _, err := net.SplitHostPort(addr)
							if err != nil {
								return nil, err
							}
							ips, err := simpledns.DNSLookup(ctx, p.requestDialer, p.dns, host, true, true)
							if err != nil {
								return nil, err
							}
							conn, err = N.DialParallel(ctx, p.requestDialer, N.NetworkUDP, M.ParseSocksaddr(addr), ips, false, 5*time.Second)
						} else {
							conn, err = p.requestDialer.DialContext(ctx, N.NetworkUDP, M.ParseSocksaddr(addr))
						}
						if err != nil {
							return nil, err
						}
						return quic.DialEarly(ctx, bufio.NewUnbindPacketConn(conn), conn.RemoteAddr(), tlsCfg, cfg)
					},
				},
			}
		}
	} else if p.httpClient == nil {
		if !p.useH3 {
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
		} else {
			httpClient = &http.Client{
				Transport: &http3.RoundTripper{
					Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
						var conn net.Conn
						var err error
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
		p.httpClient = httpClient
	} else {
		httpClient = p.httpClient
	}
	if p.requestTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, p.requestTimeout)
		defer cancel()
	}
	cache, err := request(ctx, httpClient, p.url, p.ua)
	if err != nil {
		return nil, err
	}
	if p.globalFilter != nil {
		newOutbounds := p.globalFilter.Filter(cache.Outbounds, nil)
		if len(newOutbounds) == 0 {
			return nil, E.New("no outbound available")
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
		outbound.DirectOptions.DialerOptions = newDialer
	case C.TypeHTTP:
		outbound.HTTPOptions.DialerOptions = newDialer
	case C.TypeShadowsocks:
		outbound.ShadowsocksOptions.DialerOptions = newDialer
	case C.TypeVMess:
		outbound.VMessOptions.DialerOptions = newDialer
	case C.TypeTrojan:
		outbound.TrojanOptions.DialerOptions = newDialer
	case C.TypeWireGuard:
		outbound.WireGuardOptions.DialerOptions = newDialer
	case C.TypeHysteria:
		outbound.HysteriaOptions.DialerOptions = newDialer
	case C.TypeTor:
		outbound.TorOptions.DialerOptions = newDialer
	case C.TypeSSH:
		outbound.SSHOptions.DialerOptions = newDialer
	case C.TypeShadowTLS:
		outbound.ShadowTLSOptions.DialerOptions = newDialer
	case C.TypeShadowsocksR:
		outbound.ShadowsocksROptions.DialerOptions = newDialer
	case C.TypeVLESS:
		outbound.VLESSOptions.DialerOptions = newDialer
	case C.TypeTUIC:
		outbound.TUICOptions.DialerOptions = newDialer
	case C.TypeHysteria2:
		outbound.Hysteria2Options.DialerOptions = newDialer
	case C.TypeRandomAddr:
		outbound.RandomAddrOptions.DialerOptions = newDialer
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

func ParseLink(ctx context.Context, link string) ([]option.Outbound, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, fmt.Errorf("invalid link")
	}
	switch u.Scheme {
	case "http", "https":
	default:
		// Try Raw Config
		outbound, err := raw.ParseRawLink(link)
		if err != nil {
			return nil, err
		}
		return []option.Outbound{*outbound}, nil
	}

	req, err := http.NewRequest(http.MethodGet, link, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "clash.meta; clashmeta; sing-box; singbox; SFA; SFI; SFM; SFT") // TODO: UA??

	resp, err := http.DefaultClient.Do(req.WithContext(ctx))
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("invalid http status code: %d", resp.StatusCode)
	}

	buffer := bytes.NewBuffer(nil)
	_, err = buffer.ReadFrom(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}

	data := buffer.Bytes()

	// Try Clash Config
	outbounds, err := clash.ParseClashConfig(data)
	if err != nil {
		// Try Raw Config
		outbounds, err = raw.ParseRawConfig(data)
		if err != nil {
			// Try Singbox Config
			outbounds, err = singbox.ParseSingboxConfig(data)
			if err != nil {
				return nil, fmt.Errorf("parse config failed, config is not clash config or raw links or sing-box config")
			}
		}
	}

	return outbounds, nil
}
