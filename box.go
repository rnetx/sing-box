package box

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental"
	"github.com/sagernet/sing-box/experimental/libbox/platform"
	"github.com/sagernet/sing-box/inbound"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/outbound"
	"github.com/sagernet/sing-box/route"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
)

var _ adapter.Service = (*Box)(nil)

type Box struct {
	createdAt    time.Time
	router       adapter.Router
	inbounds     []adapter.Inbound
	outbounds    []adapter.Outbound
	logFactory   log.Factory
	logger       log.ContextLogger
	logFile      *os.File
	preServices  map[string]adapter.Service
	postServices map[string]adapter.Service
	done         chan struct{}
}

func New(ctx context.Context, options option.Options, platformInterface platform.Interface) (*Box, error) {
	createdAt := time.Now()

	experimentalOptions := common.PtrValueOrDefault(options.Experimental)
	applyDebugOptions(common.PtrValueOrDefault(experimentalOptions.Debug))

	var needClashAPI bool
	var needV2RayAPI bool
	if experimentalOptions.ClashAPI != nil && experimentalOptions.ClashAPI.ExternalController != "" {
		needClashAPI = true
	}
	if experimentalOptions.V2RayAPI != nil && experimentalOptions.V2RayAPI.Listen != "" {
		needV2RayAPI = true
	}

	logOptions := common.PtrValueOrDefault(options.Log)

	var logFactory log.Factory
	var observableLogFactory log.ObservableFactory
	var logFile *os.File
	var logWriter io.Writer
	if logOptions.Disabled {
		observableLogFactory = log.NewNOPFactory()
		logFactory = observableLogFactory
	} else {
		switch logOptions.Output {
		case "":
			if platformInterface != nil {
				logWriter = io.Discard
			} else {
				logWriter = os.Stdout
			}
		case "stderr":
			logWriter = os.Stderr
		case "stdout":
			logWriter = os.Stdout
		default:
			var err error
			logFile, err = os.OpenFile(C.BasePath(logOptions.Output), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
			if err != nil {
				return nil, err
			}
			logWriter = logFile
		}
		logFormatter := log.Formatter{
			BaseTime:         createdAt,
			DisableColors:    logOptions.DisableColor || logFile != nil,
			DisableTimestamp: !logOptions.Timestamp && logFile != nil,
			FullTimestamp:    logOptions.Timestamp,
			TimestampFormat:  "-0700 2006-01-02 15:04:05",
		}
		if needClashAPI {
			observableLogFactory = log.NewObservableFactory(logFormatter, logWriter, platformInterface)
			logFactory = observableLogFactory
		} else {
			logFactory = log.NewFactory(logFormatter, logWriter, platformInterface)
		}
		if logOptions.Level != "" {
			logLevel, err := log.ParseLevel(logOptions.Level)
			if err != nil {
				return nil, E.Cause(err, "parse log level")
			}
			logFactory.SetLevel(logLevel)
		} else {
			logFactory.SetLevel(log.LevelTrace)
		}
	}

	router, err := route.NewRouter(
		ctx,
		logFactory,
		common.PtrValueOrDefault(options.Route),
		common.PtrValueOrDefault(options.DNS),
		common.PtrValueOrDefault(options.NTP),
		options.Inbounds,
		platformInterface,
	)
	if err != nil {
		return nil, E.Cause(err, "parse route options")
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
			platformInterface,
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
			outboundOptions)
		if err != nil {
			return nil, E.Cause(err, "parse outbound[", i, "]")
		}
		outbounds = append(outbounds, out)
	}
	err = router.Initialize(inbounds, outbounds, func() adapter.Outbound {
		out, oErr := outbound.New(ctx, router, logFactory.NewLogger("outbound/direct"), option.Outbound{Type: "direct", Tag: "default"})
		common.Must(oErr)
		outbounds = append(outbounds, out)
		return out
	})
	if err != nil {
		return nil, err
	}
	preServices := make(map[string]adapter.Service)
	postServices := make(map[string]adapter.Service)
	if needClashAPI {
		clashServer, err := experimental.NewClashServer(router, observableLogFactory, common.PtrValueOrDefault(options.Experimental.ClashAPI))
		if err != nil {
			return nil, E.Cause(err, "create clash api server")
		}
		router.SetClashServer(clashServer)
		preServices["clash api"] = clashServer
	}
	if needV2RayAPI {
		v2rayServer, err := experimental.NewV2RayServer(logFactory.NewLogger("v2ray-api"), common.PtrValueOrDefault(options.Experimental.V2RayAPI))
		if err != nil {
			return nil, E.Cause(err, "create v2ray api server")
		}
		router.SetV2RayServer(v2rayServer)
		preServices["v2ray api"] = v2rayServer
	}
	return &Box{
		router:       router,
		inbounds:     inbounds,
		outbounds:    outbounds,
		createdAt:    createdAt,
		logFactory:   logFactory,
		logger:       logFactory.Logger(),
		logFile:      logFile,
		preServices:  preServices,
		postServices: postServices,
		done:         make(chan struct{}),
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
		err := adapter.PreStart(service)
		if err != nil {
			return E.Cause(err, "pre-start ", serviceName)
		}
	}
	for i, out := range s.outbounds {
		if starter, isStarter := out.(common.Starter); isStarter {
			err := starter.Start()
			if err != nil {
				var tag string
				if out.Tag() == "" {
					tag = F.ToString(i)
				} else {
					tag = out.Tag()
				}
				return E.Cause(err, "initialize outbound/", out.Type(), "[", tag, "]")
			}
		}
	}
	return s.router.Start()
}

func (s *Box) start() error {
	err := s.preStart()
	if err != nil {
		return err
	}
	for serviceName, service := range s.preServices {
		err = service.Start()
		if err != nil {
			return E.Cause(err, "start ", serviceName)
		}
	}
	for i, in := range s.inbounds {
		err = in.Start()
		if err != nil {
			var tag string
			if in.Tag() == "" {
				tag = F.ToString(i)
			} else {
				tag = in.Tag()
			}
			return E.Cause(err, "initialize inbound/", in.Type(), "[", tag, "]")
		}
	}
	for serviceName, service := range s.postServices {
		err = service.Start()
		if err != nil {
			return E.Cause(err, "start ", serviceName)
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
		errors = E.Append(errors, service.Close(), func(err error) error {
			return E.Cause(err, "close ", serviceName)
		})
	}
	for i, in := range s.inbounds {
		errors = E.Append(errors, in.Close(), func(err error) error {
			return E.Cause(err, "close inbound/", in.Type(), "[", i, "]")
		})
	}
	for i, out := range s.outbounds {
		errors = E.Append(errors, common.Close(out), func(err error) error {
			return E.Cause(err, "close inbound/", out.Type(), "[", i, "]")
		})
	}
	if err := common.Close(s.router); err != nil {
		errors = E.Append(errors, err, func(err error) error {
			return E.Cause(err, "close router")
		})
	}
	for serviceName, service := range s.preServices {
		errors = E.Append(errors, service.Close(), func(err error) error {
			return E.Cause(err, "close ", serviceName)
		})
	}
	if err := common.Close(s.logFactory); err != nil {
		errors = E.Append(errors, err, func(err error) error {
			return E.Cause(err, "close log factory")
		})
	}
	if s.logFile != nil {
		errors = E.Append(errors, s.logFile.Close(), func(err error) error {
			return E.Cause(err, "close log file")
		})
	}
	return errors
}

func (s *Box) Router() adapter.Router {
	return s.router
}
