//go:build with_provider

package outbound

import (
	"bytes"
	"context"
	STDTLS "crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/outbound/provider"
	"github.com/sagernet/sing-box/outbound/provider/parse"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/batch"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

var (
	HTTPUserAgent string
	regTraffic    *regexp.Regexp
	regExpire     *regexp.Regexp
)

func init() {
	HTTPUserAgent = fmt.Sprintf(
		"clash; clash-meta; meta; SFA/%s; SFI/%s; SFT/%s; SFM/%s; sing-box/%s; sing/%s",
		C.Version,
		C.Version,
		C.Version,
		C.Version,
		C.Version,
		C.Version,
	)
	regTraffic = regexp.MustCompile(`upload=(\d+); download=(\d+); total=(\d+)`)
	regExpire = regexp.MustCompile(`expire=(\d+)`)
}

var (
	_ adapter.Outbound         = (*Provider)(nil)
	_ adapter.ProviderOutbound = (*Provider)(nil)
)

type Provider struct {
	myOutboundAdapter
	logFactory            log.Factory
	ctx                   context.Context
	dialer                N.Dialer
	url                   string
	cacheTag              string
	updateInterval        time.Duration
	requestTimeout        time.Duration
	userAgent             string
	actions               []provider.Action
	hotReload             bool
	globalOutboundOptions option.Outbound
	globalOutbound        adapter.Outbound
	outbounds             []adapter.Outbound
	outboundByTag         map[string]adapter.Outbound

	httpClient   *http.Client
	cacheFile    adapter.CacheFile
	providerInfo adapter.ProviderInfo
	loopCtx      context.Context
	loopCancel   context.CancelFunc
	closeDone    chan struct{}
	updateLock   sync.Mutex
	restartLock  sync.RWMutex
}

type ProviderData struct {
	Outbounds []option.Outbound    `json:"outbounds"`
	Info      adapter.ProviderInfo `json:"info,omitempty"`
}

func NewProvider(ctx context.Context, router adapter.Router, logFactory log.Factory, logger log.ContextLogger, tag string, options option.ProviderOutboundOptions) (adapter.Outbound, error) {
	p := &Provider{
		myOutboundAdapter: myOutboundAdapter{
			protocol:     C.TypeProvider,
			network:      []string{N.NetworkTCP, N.NetworkUDP},
			router:       router,
			logger:       logger,
			tag:          tag,
			dependencies: withDialerDependency(options.DialerOptions),
		},
		ctx:            ctx,
		logFactory:     logFactory,
		url:            options.URL,
		cacheTag:       options.CacheTag,
		updateInterval: time.Duration(options.UpdateInterval),
		requestTimeout: time.Duration(options.RequestTimeout),
		userAgent:      options.UserAgent,
		hotReload:      options.HotReload,
		globalOutboundOptions: option.Outbound{
			Tag:             tag,
			Type:            C.TypeSelector,
			SelectorOptions: options.SelectorOptions,
		},
	}
	if p.userAgent == "" {
		p.userAgent = HTTPUserAgent
	}
	if p.cacheTag == "" {
		p.cacheTag = p.tag
	}
	outboundDialer, err := dialer.New(router, options.DialerOptions)
	if err != nil {
		return nil, err
	}
	p.dialer = outboundDialer
	if len(options.Actions) > 0 {
		p.actions = make([]provider.Action, 0, len(options.Actions))
		for i, action := range options.Actions {
			a, err := provider.NewAction(action)
			if err != nil {
				return nil, E.Cause(err, "invalid action[", i, "]")
			}
			p.actions = append(p.actions, a)
		}
	}
	p.httpClient = &http.Client{}
	if !options.HTTP3 {
		p.httpClient.Transport = &http.Transport{
			ForceAttemptHTTP2: true,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return p.dialer.DialContext(ctx, network, M.ParseSocksaddr(addr))
			},
		}
	} else {
		p.httpClient.Transport = &http3.RoundTripper{
			Dial: func(ctx context.Context, addr string, tlsCfg *STDTLS.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
				destinationAddr := M.ParseSocksaddr(addr)
				conn, err := p.dialer.DialContext(ctx, N.NetworkUDP, destinationAddr)
				if err != nil {
					return nil, err
				}
				return quic.DialEarly(ctx, bufio.NewUnbindPacketConn(conn), conn.RemoteAddr(), tlsCfg, cfg)
			},
		}
	}
	return p, nil
}

func (p *Provider) preStart() error {
	outboundOptions, err := p.initOutbounds()
	if err != nil {
		return err
	}
	if len(outboundOptions) == 0 {
		return E.New("missing outbounds")
	}
	return p.prepareOutbounds(outboundOptions)
}

func (p *Provider) prepareOutbounds(outboundOptions []option.Outbound) error {
	p.outbounds = make([]adapter.Outbound, 0, len(outboundOptions))
	outboundTags := make([]string, 0, len(outboundOptions))
	p.outboundByTag = make(map[string]adapter.Outbound, len(outboundOptions))
	var err error
	for i, options := range outboundOptions {
		var out adapter.Outbound
		var tag string
		if options.Tag != "" {
			tag = options.Tag
		} else {
			tag = F.ToString(i)
		}
		out, err = New(
			p.ctx,
			p.router,
			p.logFactory,
			p.logFactory.NewLogger(F.ToString("outbound/", options.Type, "[", tag, "]")),
			tag,
			options,
		)
		if err != nil {
			return E.Cause(err, "parse outbound[", i, "]")
		}
		p.outbounds = append(p.outbounds, out)
		p.outboundByTag[tag] = out
		outboundTags = append(outboundTags, tag)
	}
	p.globalOutboundOptions.SelectorOptions.Outbounds = outboundTags
	out, err := New(
		p.ctx,
		p.router,
		p.logFactory,
		p.logFactory.NewLogger(F.ToString("outbound/", p.globalOutboundOptions.Type, "[", p.globalOutboundOptions.Tag, "]")),
		p.tag,
		p.globalOutboundOptions,
	)
	if err != nil {
		return E.Cause(err, "parse global outbound")
	}
	p.globalOutbound = out
	return nil
}

func (p *Provider) startOutbounds(outs []adapter.Outbound) ([]adapter.Outbound, error) {
	outboundTags := make(map[adapter.Outbound]string)
	outbounds := make(map[string]adapter.Outbound)
	for i, outboundToStart := range outs {
		var outboundTag string
		if outboundToStart.Tag() == "" {
			outboundTag = F.ToString(i)
		} else {
			outboundTag = outboundToStart.Tag()
		}
		if _, exists := outbounds[outboundTag]; exists {
			return nil, E.New("outbound tag ", outboundTag, " duplicated")
		}
		outboundTags[outboundToStart] = outboundTag
		outbounds[outboundTag] = outboundToStart
	}
	started := make(map[string]bool)
	startedOutbounds := make([]adapter.Outbound, 0, len(outs))
	for {
		canContinue := false
	startOne:
		for _, outboundToStart := range outs {
			outboundTag := outboundTags[outboundToStart]
			if started[outboundTag] {
				continue
			}
			dependencies := outboundToStart.Dependencies()
			for _, dependency := range dependencies {
				if !started[dependency] {
					continue startOne
				}
			}
			started[outboundTag] = true
			canContinue = true
			if starter, isStarter := outboundToStart.(common.Starter); isStarter {
				err := starter.Start()
				if err != nil {
					return nil, E.Cause(err, "initialize outbound/", outboundToStart.Type(), "[", outboundTag, "]")
				}
				startedOutbounds = append(startedOutbounds, outboundToStart)
			}
		}
		if len(started) == len(outs) {
			break
		}
		if canContinue {
			continue
		}
		currentOutbound := common.Find(outs, func(it adapter.Outbound) bool {
			return !started[outboundTags[it]]
		})
		var lintOutbound func(oTree []string, oCurrent adapter.Outbound) error
		lintOutbound = func(oTree []string, oCurrent adapter.Outbound) error {
			problemOutboundTag := common.Find(oCurrent.Dependencies(), func(it string) bool {
				return !started[it]
			})
			if common.Contains(oTree, problemOutboundTag) {
				return E.New("circular outbound dependency: ", strings.Join(oTree, " -> "), " -> ", problemOutboundTag)
			}
			problemOutbound := outbounds[problemOutboundTag]
			if problemOutbound == nil {
				return E.New("dependency[", problemOutboundTag, "] not found for outbound[", outboundTags[oCurrent], "]")
			}
			return lintOutbound(append(oTree, problemOutboundTag), problemOutbound)
		}
		return nil, lintOutbound([]string{outboundTags[currentOutbound]}, currentOutbound)
	}
	return startedOutbounds, nil
}

func (p *Provider) Start() error {
	if p.hotReload {
		p.restartLock.Lock()
		defer p.restartLock.Unlock()
	}
	err := p.preStart()
	if err != nil {
		return err
	}
	_, err = p.startOutbounds(p.outbounds)
	if err != nil {
		return err
	}
	for i, out := range p.outbounds {
		if lateOutbound, isLateOutbound := out.(adapter.PostStarter); isLateOutbound {
			err := lateOutbound.PostStart()
			if err != nil {
				return E.Cause(err, "post-start outbound/", out.Type(), "[", i, "]")
			}
		}
	}
	starter, isStarter := p.globalOutbound.(common.Starter)
	if isStarter {
		err = starter.Start()
		if err != nil {
			return E.Cause(err, "initialize global outbound")
		}
	}
	p.initCacheFile()
	if p.cacheFile != nil && p.updateInterval > 0 {
		p.loopCtx, p.loopCancel = context.WithCancel(p.ctx)
		p.closeDone = make(chan struct{}, 1)
		go p.loopUpdate()
	}
	return nil
}

func (p *Provider) Close() error {
	if p.loopCtx != nil {
		p.loopCancel()
		<-p.closeDone
		close(p.closeDone)
	}
	if p.hotReload {
		p.restartLock.Lock()
		defer p.restartLock.Unlock()
	}
	var errors error
	errors = E.Append(errors, common.Close(p.globalOutbound), func(err error) error {
		return E.Cause(err, "close global outbound")
	})
	for i, out := range p.outbounds {
		errors = E.Append(errors, common.Close(out), func(err error) error {
			return E.Cause(err, "close outbound/", out.Type(), "[", i, "]")
		})
	}
	return errors
}

func (p *Provider) PostStart() error {
	outbounds := p.outbounds
	for _, outbound := range outbounds {
		if lateOutbound, isLateOutbound := outbound.(adapter.PostStarter); isLateOutbound {
			err := lateOutbound.PostStart()
			if err != nil {
				return E.Cause(err, "post-start outbound/", outbound.Type(), "[", outbound.Tag(), "]")
			}
		}
	}
	return nil
}

func (p *Provider) InterfaceUpdated() {
	var globalOutbound adapter.Outbound
	var outbounds []adapter.Outbound
	if p.hotReload {
		p.restartLock.RLock()
		globalOutbound = p.globalOutbound
		outbounds = p.outbounds
		p.restartLock.RUnlock()
	} else {
		globalOutbound = p.globalOutbound
		outbounds = p.outbounds
	}
	if interfaceUpdated, isInterfaceUpdated := globalOutbound.(adapter.InterfaceUpdateListener); isInterfaceUpdated {
		interfaceUpdated.InterfaceUpdated()
	}
	for _, out := range outbounds {
		if interfaceUpdated, isInterfaceUpdated := out.(adapter.InterfaceUpdateListener); isInterfaceUpdated {
			interfaceUpdated.InterfaceUpdated()
		}
	}
}

func (p *Provider) Network() []string {
	globalOutbound := p.globalOutbound
	if globalOutbound == nil {
		return []string{N.NetworkTCP, N.NetworkUDP}
	}
	return globalOutbound.Network()
}

func (p *Provider) Now() string {
	globalOutbound := p.globalOutbound
	return globalOutbound.(*Selector).Now()
}

func (p *Provider) All() []string {
	globalOutbound := p.globalOutbound
	return globalOutbound.(*Selector).All()
}

func (p *Provider) SelectOutbound(tag string) bool {
	globalOutbound := p.globalOutbound
	return globalOutbound.(*Selector).SelectOutbound(tag)
}

func (p *Provider) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return p.globalOutbound.DialContext(ctx, network, destination)
}

func (p *Provider) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return p.globalOutbound.ListenPacket(ctx, destination)
}

func (p *Provider) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	return p.globalOutbound.NewConnection(ctx, conn, metadata)
}

func (p *Provider) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	return p.globalOutbound.NewPacketConnection(ctx, conn, metadata)
}

func (p *Provider) Outbounds() []adapter.Outbound {
	return p.outbounds
}

func (p *Provider) Outbound(tag string) (adapter.Outbound, bool) {
	outboundByTag := p.outboundByTag
	outbound, loaded := outboundByTag[tag]
	return outbound, loaded
}

func (p *Provider) CallUpdate() {
	if p.updateLock.TryLock() {
		p.update()
		p.updateLock.Unlock()
	}
}

func (p *Provider) HealthCheck(_ context.Context, url string) error {
	ctx, cancel := context.WithCancel(p.ctx)
	defer cancel()

	var urlTestHistory *urltest.HistoryStorage
	clashServer := p.router.ClashServer()
	if clashServer != nil {
		urlTestHistory = clashServer.HistoryStorage()
	}

	b, _ := batch.New(ctx, batch.WithConcurrencyNum[any](32))
	outbounds := p.outbounds
	for _, outbound := range outbounds {
		tag := outbound.Tag()
		b.Go(tag, func() (any, error) {
			t, err := urltest.URLTest(ctx, url, outbound)
			if err != nil {
				p.logger.Debug("outbound ", tag, " unavailable: ", err)
				if urlTestHistory != nil {
					urlTestHistory.DeleteURLTestHistory(tag)
				}
			} else {
				p.logger.Debug("outbound ", tag, " available: ", t, "ms")
				if urlTestHistory != nil {
					urlTestHistory.StoreURLTestHistory(tag, &urltest.History{
						Time:  time.Now(),
						Delay: t,
					})
				}
			}
			return nil, nil
		})
	}

	return b.Wait()
}

func (p *Provider) ProviderInfo() adapter.ProviderInfo {
	return p.providerInfo
}

func (p *Provider) loopUpdate() {
	defer func() {
		select {
		case p.closeDone <- struct{}{}:
		default:
		}
	}()
	p.logger.Info("start update loop")
	ticker := time.NewTicker(p.updateInterval)
	defer ticker.Stop()
	for {
		select {
		case <-p.loopCtx.Done():
			return
		case <-ticker.C:
			if p.updateLock.TryLock() {
				p.update()
				p.updateLock.Unlock()
			}
		}
	}
}

func (p *Provider) initOutbounds() ([]option.Outbound, error) {
	var (
		providerData ProviderData
		err          error
	)
	p.initCacheFile()
	if p.cacheFile != nil {
		providerData, _ = p.loadProviderData()
	}
	if len(providerData.Outbounds) == 0 || (p.updateInterval > 0 && time.Since(providerData.Info.UpdateTime) > p.updateInterval) {
		providerData, err = p.fetch(p.ctx)
		if err == nil {
			if p.cacheFile != nil {
				err = p.storeProviderData(providerData)
				if err != nil {
					p.logger.Error("store provider data failed: ", err)
				}
			}
		} else {
			if len(providerData.Outbounds) > 0 {
				p.logger.Warn("fetch provider data failed: ", err)
			} else {
				return nil, err
			}
		}
	}
	p.providerInfo = providerData.Info
	set := provider.NewPreProcessSet(providerData.Outbounds, p.actions)
	return set.Build()
}

func (p *Provider) initCacheFile() {
	if p.cacheFile == nil {
		p.cacheFile = service.FromContext[adapter.CacheFile](p.ctx)
	}
}

func (p *Provider) fetch(ctx context.Context) (ProviderData, error) {
	if p.requestTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, p.requestTimeout)
		defer cancel()
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, p.url, nil)
	if err != nil {
		return ProviderData{}, err
	}
	httpReq.Header.Set("User-Agent", p.userAgent)
	httpResp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return ProviderData{}, err
	}
	buffer := bytes.NewBuffer(nil)
	_, err = io.Copy(buffer, httpResp.Body)
	httpResp.Body.Close()
	if err != nil {
		return ProviderData{}, err
	}
	outbounds, err := parse.Parse(buffer.Bytes())
	if err != nil {
		return ProviderData{}, err
	}
	providerData := ProviderData{
		Outbounds: outbounds,
	}
	providerData.Info.UpdateTime = time.Now()
	subscriptionUserInfo := httpResp.Header.Get("subscription-userinfo")
	if subscriptionUserInfo != "" {
		subscriptionUserInfo = strings.ToLower(subscriptionUserInfo)
		matchTraffic := regTraffic.FindStringSubmatch(subscriptionUserInfo)
		if len(matchTraffic) == 4 {
			uploadUint64, err := strconv.ParseUint(matchTraffic[1], 10, 64)
			if err == nil {
				providerData.Info.Upload = uploadUint64
			}
			downloadUint64, err := strconv.ParseUint(matchTraffic[2], 10, 64)
			if err == nil {
				providerData.Info.Download = downloadUint64
			}
			totalUint64, err := strconv.ParseUint(matchTraffic[3], 10, 64)
			if err == nil {
				providerData.Info.Total = totalUint64
			}
		}
		matchExpire := regExpire.FindStringSubmatch(subscriptionUserInfo)
		if len(matchExpire) == 2 {
			expireUint64, err := strconv.ParseUint(matchExpire[1], 10, 64)
			if err == nil {
				providerData.Info.ExpireTime = time.Unix(int64(expireUint64), 0)
			}
		}
	}
	return providerData, nil
}

func (p *Provider) loadProviderData() (ProviderData, error) {
	raw, err := p.cacheFile.LoadProviderOutboundData(p.cacheTag)
	if err != nil {
		return ProviderData{}, err
	}
	var providerData ProviderData
	err = json.Unmarshal(raw, &providerData)
	if err != nil {
		return ProviderData{}, err
	}
	return providerData, nil
}

func (p *Provider) storeProviderData(providerData ProviderData) error {
	raw, err := json.Marshal(providerData)
	if err != nil {
		return err
	}
	return p.cacheFile.StoreProviderOutboundData(p.cacheTag, raw)
}

func (p *Provider) update() {
	p.initCacheFile()
	if p.cacheFile != nil || p.hotReload {
		p.logger.Info("update provider data...")
		defer p.logger.Info("update provider data done")
		providerData, err := p.fetch(p.ctx)
		if err != nil {
			p.logger.Error("fetch provider data failed: ", err)
			return
		}
		p.providerInfo = providerData.Info
		if p.cacheFile != nil {
			err = p.storeProviderData(providerData)
			if err != nil {
				p.logger.Error("store provider data failed: ", err)
				return
			}
		}
		if p.hotReload {
			set := provider.NewPreProcessSet(providerData.Outbounds, p.actions)
			outbounds, err := set.Build()
			if err != nil {
				p.logger.Error("build outbounds failed: ", err)
				return
			}
			err = p.restartOutbounds(outbounds)
			if err != nil {
				p.logger.Error("restart outbounds failed: ", err)
			}
			// GC
			runtime.GC()
		}
	}
}

func (p *Provider) restartOutbounds(outboundOptions []option.Outbound) (err error) {
	outbounds := make([]adapter.Outbound, 0, len(outboundOptions))
	outboundTags := make([]string, 0, len(outboundOptions))
	outboundByTag := make(map[string]adapter.Outbound, len(outboundOptions))
	for i, options := range outboundOptions {
		var out adapter.Outbound
		var tag string
		if options.Tag != "" {
			tag = options.Tag
		} else {
			tag = F.ToString(i)
		}
		out, err = New(
			p.ctx,
			p.router,
			p.logFactory,
			p.logFactory.NewLogger(F.ToString("outbound/", options.Type, "[", tag, "]")),
			tag,
			options,
		)
		if err != nil {
			err = E.Cause(err, "restart: parse new outbound[", i, "]")
			return
		}
		defer func(out adapter.Outbound) {
			if err != nil {
				err := common.Close(out)
				if err != nil {
					p.logger.Warn("restart: close new outbound/", out.Type(), "[", out.Tag(), "] failed: ", err)
				}
			}
		}(out)
		p.outbounds = append(p.outbounds, out)
		p.outboundByTag[tag] = out
		outboundTags = append(outboundTags, tag)
	}
	p.globalOutboundOptions.SelectorOptions.Outbounds = outboundTags
	var globalOutbound adapter.Outbound
	globalOutbound, err = New(
		p.ctx,
		p.router,
		p.logFactory,
		p.logFactory.NewLogger(F.ToString("outbound/", p.globalOutboundOptions.Type, "[", p.globalOutboundOptions.Tag, "]")),
		p.tag,
		p.globalOutboundOptions,
	)
	if err != nil {
		err = E.Cause(err, "restart: parse new global outbound")
		return
	}
	defer func() {
		if err != nil {
			err := common.Close(p.globalOutbound)
			if err != nil {
				p.logger.Warn("restart: close new global outbound failed: ", err)
			}
		}
	}()
	// Start New Outbounds
	var startedOutbounds []adapter.Outbound
	startedOutbounds, err = p.startOutbounds(outbounds)
	if err != nil {
		err = E.Cause(err, "restart: start new outbounds")
		for _, out := range startedOutbounds {
			err := common.Close(out)
			if err != nil {
				p.logger.Warn("restart: close new outbound/", out.Type(), "[", out.Tag(), "] failed: ", err)
			}
		}
		return
	}
	defer func() {
		if err != nil {
			for _, out := range startedOutbounds {
				err := common.Close(out)
				if err != nil {
					p.logger.Warn("restart: close new outbound/", out.Type(), "[", out.Tag(), "] failed: ", err)
				}
			}
		}
	}()
	starter, isStarter := globalOutbound.(common.Starter)
	if isStarter {
		err = starter.Start()
		if err != nil {
			err = E.Cause(err, "initialize new global outbound")
			return
		}
	}
	defer func() {
		if err != nil {
			err := common.Close(globalOutbound)
			if err != nil {
				p.logger.Warn("restart: close new global outbound failed: ", err)
			}
		}
	}()
	for _, out := range startedOutbounds {
		if lateOutbound, isLateOutbound := out.(adapter.PostStarter); isLateOutbound {
			err = lateOutbound.PostStart()
			if err != nil {
				err = E.Cause(err, "restart: post-start new outbound/", out.Type(), "[", out.Tag(), "]")
				return
			}
			defer func(out adapter.Outbound) {
				if err != nil {
					err := common.Close(out)
					if err != nil {
						p.logger.Warn("restart: post-start new outbound/", out.Type(), "[", out.Tag(), "] failed: ", err)
					}
				}
			}(out)
		}
	}
	// Restart
	p.restartLock.Lock()
	oldOutbounds := p.outbounds
	oldGlobalOutbound := p.globalOutbound
	p.outbounds = outbounds
	p.outboundByTag = outboundByTag
	p.globalOutbound = globalOutbound
	p.restartLock.Unlock()
	// Close Old Outbounds
	err = common.Close(oldGlobalOutbound)
	if err != nil {
		p.logger.Warn("restart: close old global outbound failed: ", err)
	}
	err = nil
	for _, out := range oldOutbounds {
		err := common.Close(out)
		if err != nil {
			p.logger.Warn("restart: close old outbound/", out.Type(), "[", out.Tag(), "] failed: ", err)
		}
	}
	return nil
}
