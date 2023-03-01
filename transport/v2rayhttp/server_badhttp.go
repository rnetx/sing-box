//go:build go1.20 && !go1.21

package v2rayhttp

import (
	std_bufio "bufio"
	"context"
	"net"
	stdHTTP "net/http"
	"os"
	"strings"
	"unsafe"

	"github.com/sagernet/badhttp"
	"github.com/sagernet/badhttp2"
	"github.com/sagernet/badhttp2/h2c"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	sHttp "github.com/sagernet/sing/protocol/http"
)

var _ adapter.V2RayServerTransport = (*Server)(nil)

type Server struct {
	ctx        context.Context
	handler    adapter.V2RayServerTransportHandler
	httpServer *http.Server
	h2Server   *http2.Server
	h2cHandler http.Handler
	host       []string
	path       string
	method     string
	headers    http.Header
}

func (s *Server) Network() []string {
	return []string{N.NetworkTCP}
}

func NewServer(ctx context.Context, options option.V2RayHTTPOptions, tlsConfig tls.ServerConfig, handler adapter.V2RayServerTransportHandler) (*Server, error) {
	server := &Server{
		ctx:      ctx,
		handler:  handler,
		h2Server: new(http2.Server),
		host:     options.Host,
		path:     options.Path,
		method:   options.Method,
		headers:  make(http.Header),
	}
	if server.method == "" {
		server.method = "PUT"
	}
	if !strings.HasPrefix(server.path, "/") {
		server.path = "/" + server.path
	}
	for key, value := range options.Headers {
		server.headers.Set(key, value)
	}
	server.httpServer = &http.Server{
		Handler:           server,
		ReadHeaderTimeout: C.TCPTimeout,
		MaxHeaderBytes:    http.DefaultMaxHeaderBytes,
		TLSConfig:         tlsConfig,
	}
	server.h2cHandler = h2c.NewHandler(server, server.h2Server)
	return server, nil
}

func (s *Server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Method == "PRI" && len(request.Header) == 0 && request.URL.Path == "*" && request.Proto == "HTTP/2.0" {
		s.h2cHandler.ServeHTTP(writer, request)
		return
	}
	host := request.Host
	if len(s.host) > 0 && !common.Contains(s.host, host) {
		s.fallbackRequest(request.Context(), writer, request, http.StatusBadRequest, E.New("bad host: ", host))
		return
	}
	if !strings.HasPrefix(request.URL.Path, s.path) {
		s.fallbackRequest(request.Context(), writer, request, http.StatusNotFound, E.New("bad path: ", request.URL.Path))
		return
	}
	if request.Method != s.method {
		s.fallbackRequest(request.Context(), writer, request, http.StatusNotFound, E.New("bad method: ", request.Method))
		return
	}

	writer.Header().Set("Cache-Control", "no-store")

	for key, values := range s.headers {
		for _, value := range values {
			writer.Header().Set(key, value)
		}
	}

	writer.WriteHeader(http.StatusOK)
	writer.(http.Flusher).Flush()

	var metadata M.Metadata
	metadata.Source = sHttp.SourceAddress(BadRequest(request))
	if h, ok := writer.(http.Hijacker); ok {
		conn, _, err := h.Hijack()
		if err != nil {
			s.fallbackRequest(request.Context(), writer, request, http.StatusInternalServerError, E.Cause(err, "hijack conn"))
			return
		}
		s.handler.NewConnection(request.Context(), conn, metadata)
	} else {
		conn := NewHTTP2Wrapper(&ServerHTTPConn{
			NewHTTPConn(request.Body, writer),
			writer.(http.Flusher),
		})
		s.handler.NewConnection(request.Context(), conn, metadata)
		conn.CloseWrapper()
	}
}

func (s *Server) fallbackRequest(ctx context.Context, writer http.ResponseWriter, request *http.Request, statusCode int, err error) {
	conn := NewHTTPConn(request.Body, writer)
	fErr := s.handler.FallbackConnection(ctx, &conn, M.Metadata{})
	if fErr == nil {
		return
	} else if fErr == os.ErrInvalid {
		fErr = nil
	}
	writer.WriteHeader(statusCode)
	s.handler.NewError(request.Context(), E.Cause(E.Errors(err, E.Cause(fErr, "fallback connection")), "process connection from ", request.RemoteAddr))
}

func (s *Server) Serve(listener net.Listener) error {
	if s.httpServer.TLSConfig != nil {
		err := http2.ConfigureServer(s.httpServer, s.h2Server)
		if err != nil {
			return err
		}
		return s.httpServer.ServeTLS(listener, "", "")
	} else {
		return s.httpServer.Serve(listener)
	}
}

func (s *Server) ServePacket(listener net.PacketConn) error {
	return os.ErrInvalid
}

func (s *Server) Close() error {
	return common.Close(common.PtrOrNil(s.httpServer))
}

var (
	_ stdHTTP.ResponseWriter = (*BadResponseWriter)(nil)
	_ stdHTTP.Hijacker       = (*BadResponseWriter)(nil)
)

type BadResponseWriter struct {
	http.ResponseWriter
}

func (w *BadResponseWriter) Header() stdHTTP.Header {
	return stdHTTP.Header(w.ResponseWriter.Header())
}

func (w *BadResponseWriter) Hijack() (net.Conn, *std_bufio.ReadWriter, error) {
	if hijacker, loaded := common.Cast[http.Hijacker](w.ResponseWriter); loaded {
		return hijacker.Hijack()
	}
	return nil, nil, os.ErrInvalid
}

func BadRequest(r *http.Request) *stdHTTP.Request {
	return (*stdHTTP.Request)(unsafe.Pointer(r))
}
