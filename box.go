package box

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/experimental"
	"github.com/sagernet/sing-box/experimental/libbox/platform"
	"github.com/sagernet/sing-box/inbound"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/outbound"
	"github.com/sagernet/sing-box/proxyprovider"
	"github.com/sagernet/sing-box/route"
	"github.com/sagernet/sing-box/ruleprovider"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
)

var _ adapter.Service = (*Box)(nil)

type Box struct {
	createdAt      time.Time
	router         adapter.Router
	inbounds       []adapter.Inbound
	outbounds      []adapter.Outbound
	proxyProviders []adapter.ProxyProvider
	ruleProviders  []adapter.RuleProvider
	logFactory     log.Factory
	logger         log.ContextLogger
	preServices    map[string]adapter.Service
	postServices   map[string]adapter.Service
	reloadChan     chan struct{}
	done           chan struct{}
}

type Options struct {
	option.Options
	Context           context.Context
	PlatformInterface platform.Interface
}

func New(options Options) (*Box, error) {
	ctx := options.Context
	if ctx == nil {
		ctx = context.Background()
	}
	ctx = service.ContextWithDefaultRegistry(ctx)
	ctx = pause.ContextWithDefaultManager(ctx)
	createdAt := time.Now()
	reloadChan := make(chan struct{}, 1)
	experimentalOptions := common.PtrValueOrDefault(options.Experimental)
	applyDebugOptions(common.PtrValueOrDefault(experimentalOptions.Debug))
	var needClashAPI bool
	var needV2RayAPI bool
	if experimentalOptions.ClashAPI != nil || options.PlatformInterface != nil {
		needClashAPI = true
	}
	if experimentalOptions.V2RayAPI != nil && experimentalOptions.V2RayAPI.Listen != "" {
		needV2RayAPI = true
	}
	var defaultLogWriter io.Writer
	if options.PlatformInterface != nil {
		defaultLogWriter = io.Discard
	}
	logFactory, err := log.New(log.Options{
		Context:        ctx,
		Options:        common.PtrValueOrDefault(options.Log),
		Observable:     needClashAPI,
		DefaultWriter:  defaultLogWriter,
		BaseTime:       createdAt,
		PlatformWriter: options.PlatformInterface,
	})
	if err != nil {
		return nil, E.Cause(err, "create log factory")
	}
	routeOptions := common.PtrValueOrDefault(options.Route)
	dnsOptions := common.PtrValueOrDefault(options.DNS)
	var ruleProviders []adapter.RuleProvider
	if len(options.RulProviders) > 0 {
		ruleProviders = make([]adapter.RuleProvider, 0, len(options.RulProviders))
		for i, ruleProviderOptions := range options.RulProviders {
			var rp adapter.RuleProvider
			var tag string
			if ruleProviderOptions.Tag != "" {
				tag = ruleProviderOptions.Tag
			} else {
				tag = F.ToString(i)
				ruleProviderOptions.Tag = tag
			}
			rp, err = ruleprovider.NewRuleProvider(ctx, logFactory.NewLogger(F.ToString("ruleprovider[", tag, "]")), tag, ruleProviderOptions)
			if err != nil {
				return nil, E.Cause(err, "parse ruleprovider[", i, "]")
			}
			var dnsRules *[]option.DNSRule
			var routeRules *[]option.Rule
			if routeOptions.Rules != nil && len(routeOptions.Rules) > 0 {
				routeRules = &routeOptions.Rules
			}
			if dnsOptions.Rules != nil && len(dnsOptions.Rules) > 0 {
				dnsRules = &dnsOptions.Rules
			}
			newDNSRules, newRouteRules, err := rp.FormatRule(dnsRules, routeRules)
			if err != nil {
				return nil, E.Cause(err, "ruleprovider[", i, "] format rule")
			}
			if routeOptions.Rules != nil && len(routeOptions.Rules) > 0 {
				routeOptions.Rules = newRouteRules
			}
			if dnsOptions.Rules != nil && len(dnsOptions.Rules) > 0 {
				dnsOptions.Rules = newDNSRules
			}
			ruleProviders = append(ruleProviders, rp)
		}
	}
	router, err := route.NewRouter(
		ctx,
		logFactory,
		routeOptions,
		dnsOptions,
		common.PtrValueOrDefault(options.NTP),
		options.Inbounds,
		options.PlatformInterface,
		reloadChan,
	)
	if err != nil {
		return nil, E.Cause(err, "parse route options")
	}
	if len(ruleProviders) > 0 {
		for _, ruleProvider := range ruleProviders {
			ruleProvider.SetRouter(router)
		}
	}
	inbounds := make([]adapter.Inbound, 0, len(options.Inbounds))
	outbounds := make([]adapter.Outbound, 0, len(options.Outbounds))
	for i, inboundOptions := range options.Inbounds {
		var in adapter.Inbound
		var tag string
		if inboundOptions.Tag != "" {
			tag = inboundOptions.Tag
		} else {
			tag = F.ToString(i)
		}
		in, err = inbound.New(
			ctx,
			router,
			logFactory.NewLogger(F.ToString("inbound/", inboundOptions.Type, "[", tag, "]")),
			inboundOptions,
			options.PlatformInterface,
		)
		if err != nil {
			return nil, E.Cause(err, "parse inbound[", i, "]")
		}
		inbounds = append(inbounds, in)
	}
	for i, outboundOptions := range options.Outbounds {
		var out adapter.Outbound
		var tag string
		if outboundOptions.Tag != "" {
			tag = outboundOptions.Tag
		} else {
			tag = F.ToString(i)
		}
		out, err = outbound.New(
			ctx,
			router,
			logFactory.NewLogger(F.ToString("outbound/", outboundOptions.Type, "[", tag, "]")),
			tag,
			outboundOptions)
		if err != nil {
			return nil, E.Cause(err, "parse outbound[", i, "]")
		}
		outbounds = append(outbounds, out)
	}
	var proxyProviders []adapter.ProxyProvider
	if len(options.ProxyProviders) > 0 {
		proxyProviders = make([]adapter.ProxyProvider, 0, len(options.ProxyProviders))
		for i, proxyProviderOptions := range options.ProxyProviders {
			var pp adapter.ProxyProvider
			var tag string
			if proxyProviderOptions.Tag != "" {
				tag = proxyProviderOptions.Tag
			} else {
				tag = F.ToString(i)
				proxyProviderOptions.Tag = tag
			}
			pp, err = proxyprovider.NewProxyProvider(ctx, router, logFactory.NewLogger(F.ToString("proxyprovider[", tag, "]")), tag, proxyProviderOptions)
			if err != nil {
				return nil, E.Cause(err, "parse proxyprovider[", i, "]")
			}
			outboundOptions, err := pp.StartGetOutbounds()
			if err != nil {
				return nil, E.Cause(err, "get outbounds from proxyprovider[", i, "]")
			}
			for i, outboundOptions := range outboundOptions {
				var out adapter.Outbound
				tag := outboundOptions.Tag
				out, err = outbound.New(
					ctx,
					router,
					logFactory.NewLogger(F.ToString("outbound/", outboundOptions.Type, "[", tag, "]")),
					tag,
					outboundOptions)
				if err != nil {
					return nil, E.Cause(err, "parse proxyprovider ["+pp.Tag()+"] outbound[", i, "]")
				}
				outbounds = append(outbounds, out)
			}
			proxyProviders = append(proxyProviders, pp)
		}
	}
	err = router.Initialize(inbounds, outbounds, func() adapter.Outbound {
		out, oErr := outbound.New(ctx, router, logFactory.NewLogger("outbound/direct"), "direct", option.Outbound{Type: "direct", Tag: "default"})
		common.Must(oErr)
		outbounds = append(outbounds, out)
		return out
	}, proxyProviders, ruleProviders)
	if err != nil {
		return nil, err
	}
	if options.PlatformInterface != nil {
		err = options.PlatformInterface.Initialize(ctx, router)
		if err != nil {
			return nil, E.Cause(err, "initialize platform interface")
		}
	}
	preServices := make(map[string]adapter.Service)
	postServices := make(map[string]adapter.Service)
	if needClashAPI {
		clashAPIOptions := common.PtrValueOrDefault(experimentalOptions.ClashAPI)
		clashAPIOptions.ModeList = experimental.CalculateClashModeList(options.Options)
		clashServer, err := experimental.NewClashServer(ctx, router, logFactory.(log.ObservableFactory), clashAPIOptions)
		if err != nil {
			return nil, E.Cause(err, "create clash api server")
		}
		router.SetClashServer(clashServer)
		preServices["clash api"] = clashServer
	}
	if needV2RayAPI {
		v2rayServer, err := experimental.NewV2RayServer(logFactory.NewLogger("v2ray-api"), common.PtrValueOrDefault(experimentalOptions.V2RayAPI))
		if err != nil {
			return nil, E.Cause(err, "create v2ray api server")
		}
		router.SetV2RayServer(v2rayServer)
		preServices["v2ray api"] = v2rayServer
	}
	return &Box{
		router:         router,
		inbounds:       inbounds,
		outbounds:      outbounds,
		proxyProviders: proxyProviders,
		ruleProviders:  ruleProviders,
		createdAt:      createdAt,
		logFactory:     logFactory,
		logger:         logFactory.Logger(),
		preServices:    preServices,
		postServices:   postServices,
		done:           make(chan struct{}),
		reloadChan:     reloadChan,
	}, nil
}

func (s *Box) PreStart() error {
	err := s.preStart()
	if err != nil {
		// TODO: remove catch error
		defer func() {
			v := recover()
			if v != nil {
				log.Error(E.Cause(err, "origin error"))
				debug.PrintStack()
				panic("panic on early close: " + fmt.Sprint(v))
			}
		}()
		s.Close()
		return err
	}
	s.logger.Info("sing-box pre-started (", F.Seconds(time.Since(s.createdAt).Seconds()), "s)")
	return nil
}

func (s *Box) Start() error {
	err := s.start()
	if err != nil {
		// TODO: remove catch error
		defer func() {
			v := recover()
			if v != nil {
				log.Error(E.Cause(err, "origin error"))
				debug.PrintStack()
				panic("panic on early close: " + fmt.Sprint(v))
			}
		}()
		s.Close()
		return err
	}
	s.logger.Info("sing-box started (", F.Seconds(time.Since(s.createdAt).Seconds()), "s)")
	return nil
}

func (s *Box) preStart() error {
	for serviceName, service := range s.preServices {
		if preService, isPreService := service.(adapter.PreStarter); isPreService {
			s.logger.Trace("pre-start ", serviceName)
			err := preService.PreStart()
			if err != nil {
				return E.Cause(err, "pre-starting ", serviceName)
			}
		}
	}
	err := s.startOutbounds()
	if err != nil {
		return err
	}
	return s.router.Start()
}

func (s *Box) start() error {
	err := s.preStart()
	if err != nil {
		return err
	}
	for serviceName, service := range s.preServices {
		s.logger.Trace("starting ", serviceName)
		err = service.Start()
		if err != nil {
			return E.Cause(err, "start ", serviceName)
		}
	}
	for _, proxyProvider := range s.proxyProviders {
		s.logger.Trace("starting proxyprovider ", proxyProvider.Tag())
		err = proxyProvider.Start()
		if err != nil {
			return E.Cause(err, "start proxyprovider ", proxyProvider.Tag())
		}
	}
	for _, ruleProvider := range s.ruleProviders {
		s.logger.Trace("starting ruleprovider ", ruleProvider.Tag())
		err = ruleProvider.Start()
		if err != nil {
			return E.Cause(err, "start ruleprovider ", ruleProvider.Tag())
		}
	}
	for i, in := range s.inbounds {
		var tag string
		if in.Tag() == "" {
			tag = F.ToString(i)
		} else {
			tag = in.Tag()
		}
		s.logger.Trace("initializing inbound/", in.Type(), "[", tag, "]")
		err = in.Start()
		if err != nil {
			return E.Cause(err, "initialize inbound/", in.Type(), "[", tag, "]")
		}
	}
	return nil
}

func (s *Box) postStart() error {
	for serviceName, service := range s.postServices {
		s.logger.Trace("starting ", service)
		err := service.Start()
		if err != nil {
			return E.Cause(err, "start ", serviceName)
		}
	}
	for serviceName, service := range s.outbounds {
		if lateService, isLateService := service.(adapter.PostStarter); isLateService {
			s.logger.Trace("post-starting ", service)
			err := lateService.PostStart()
			if err != nil {
				return E.Cause(err, "post-start ", serviceName)
			}
		}
	}
	return nil
}

func (s *Box) Close() error {
	select {
	case <-s.done:
		return os.ErrClosed
	default:
		close(s.done)
	}
	var errors error
	for serviceName, service := range s.postServices {
		s.logger.Trace("closing ", serviceName)
		errors = E.Append(errors, service.Close(), func(err error) error {
			return E.Cause(err, "close ", serviceName)
		})
	}
	for _, ruleProvider := range s.ruleProviders {
		s.logger.Trace("closing ruleprovider ", ruleProvider.Tag())
		errors = E.Append(errors, ruleProvider.Close(), func(err error) error {
			return E.Cause(err, "close ruleprovider ", ruleProvider.Tag())
		})
	}
	for _, proxyProvider := range s.proxyProviders {
		s.logger.Trace("closing proxyprovider ", proxyProvider.Tag())
		errors = E.Append(errors, proxyProvider.Close(), func(err error) error {
			return E.Cause(err, "close proxyprovider ", proxyProvider.Tag())
		})
	}
	for i, in := range s.inbounds {
		s.logger.Trace("closing inbound/", in.Type(), "[", i, "]")
		errors = E.Append(errors, in.Close(), func(err error) error {
			return E.Cause(err, "close inbound/", in.Type(), "[", i, "]")
		})
	}
	for i, out := range s.outbounds {
		s.logger.Trace("closing outbound/", out.Type(), "[", i, "]")
		errors = E.Append(errors, common.Close(out), func(err error) error {
			return E.Cause(err, "close outbound/", out.Type(), "[", i, "]")
		})
	}
	s.logger.Trace("closing router")
	if err := common.Close(s.router); err != nil {
		errors = E.Append(errors, err, func(err error) error {
			return E.Cause(err, "close router")
		})
	}
	for serviceName, service := range s.preServices {
		s.logger.Trace("closing ", serviceName)
		errors = E.Append(errors, service.Close(), func(err error) error {
			return E.Cause(err, "close ", serviceName)
		})
	}
	s.logger.Trace("closing log factory")
	if err := common.Close(s.logFactory); err != nil {
		errors = E.Append(errors, err, func(err error) error {
			return E.Cause(err, "close log factory")
		})
	}
	return errors
}

func (s *Box) Router() adapter.Router {
	return s.router
}

func (s *Box) ReloadChan() <-chan struct{} {
	return s.reloadChan
}
