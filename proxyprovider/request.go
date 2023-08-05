//go:build with_proxyprovider

package proxyprovider

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/proxyprovider/proxy"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"gopkg.in/yaml.v3"
)

const requestTimeout = 10 * time.Second

func (p *ProxyProvider) update() error {
	cache, cacheTime, cacheErr := p.readCache()
	if cacheErr == nil {
		if p.options.ForceUpdate == 0 || time.Since(cacheTime) < time.Duration(p.options.ForceUpdate) {
			p.subscriptionRawDataLock.Lock()
			p.subscriptionRawData = *cache
			p.subscriptionRawDataLock.Unlock()
			return nil
		}
	}

	rawData, err := p.request()
	if err != nil {
		if cacheErr == nil {
			if p.logger != nil {
				p.logger.Warn("failed to update proxy provider, use cache, err: ", err)
			}
			p.subscriptionRawDataLock.Lock()
			p.subscriptionRawData = *cache
			p.subscriptionRawDataLock.Unlock()
			return nil
		}
		return E.Cause(err, "failed to update proxy provider")
	}

	p.subscriptionRawDataLock.Lock()
	p.subscriptionRawData = *rawData
	p.subscriptionRawDataLock.Unlock()

	err = p.writeCache()
	if err != nil {
		return err
	}

	return nil
}

func (p *ProxyProvider) Update() error {
	if !p.updateLock.TryLock() {
		return nil
	}
	defer p.updateLock.Unlock()

	err := p.update()
	if err != nil {
		return err
	}

	return p.parseToPeerList()
}

func (p *ProxyProvider) ForceUpdate() error {
	if !p.updateLock.TryLock() {
		return nil
	}
	defer p.updateLock.Unlock()

	rawData, err := p.request()
	if err != nil {
		return E.Cause(err, "failed to update proxy provider")
	}

	p.subscriptionRawDataLock.Lock()
	p.subscriptionRawData = *rawData
	p.subscriptionRawDataLock.Unlock()

	err = p.writeCache()
	if err != nil {
		return err
	}

	return p.parseToPeerList()
}

func (p *ProxyProvider) parseToPeerList() error {
	var clashConfig proxy.ClashConfig
	p.subscriptionRawDataLock.RLock()
	PeerInfo := p.subscriptionRawData.PeerInfo
	p.subscriptionRawDataLock.RUnlock()
	err := yaml.Unmarshal(PeerInfo, &clashConfig)
	if err != nil {
		return E.Cause(err, "failed to parse proxy")
	}
	if clashConfig.Proxies == nil || len(clashConfig.Proxies) == 0 {
		return E.New("proxy not found")
	}

	proxies := make([]proxy.Proxy, 0)
	for _, proxyConfig := range clashConfig.Proxies {
		px, err := proxyConfig.ToProxy()
		if err != nil {
			return E.Cause(err, "failed to parse proxy")
		}
		if !CheckFilter(p.options.Filter, px.Tag(), px.Type()) {
			continue
		}
		if p.options.DialerOptions != nil {
			px.SetDialerOptions(*p.options.DialerOptions)
		}
		proxies = append(proxies, px)
	}

	p.peerList = proxies

	return nil
}

func (p *ProxyProvider) readCache() (*subscriptionRawData, time.Time, error) {
	file, err := os.Open(p.options.CacheFile)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer file.Close()
	fileInfo, err := file.Stat()
	if err != nil {
		return nil, time.Time{}, err
	}
	data := make([]byte, fileInfo.Size())
	var n int
	n, err = file.Read(data)
	if err != nil {
		return nil, time.Time{}, err
	}
	if n == 0 {
		return nil, time.Time{}, E.New("cache file is empty")
	}
	var s subscriptionRawData
	err = s.decode(data)
	if err != nil {
		return nil, time.Time{}, err
	}
	return &s, fileInfo.ModTime(), nil
}

func (p *ProxyProvider) writeCache() error {
	if p.options.CacheFile != "" {
		p.subscriptionRawDataLock.RLock()
		subscriptionRawData := p.subscriptionRawData
		p.subscriptionRawDataLock.RUnlock()
		data, err := subscriptionRawData.encode()
		if err != nil {
			return err
		}
		return os.WriteFile(p.options.CacheFile, data, 0o644)
	}

	return nil
}

func (p *ProxyProvider) request() (*subscriptionRawData, error) {
	req, err := http.NewRequest(http.MethodGet, p.options.URL, nil)
	if err != nil {
		return nil, E.Cause(err, "failed to create http request")
	}
	req.Header.Set("User-Agent", "clash")
	header, data, err := p.httpRequest(req)
	if err != nil {
		return nil, E.Cause(err, "failed to request")
	}
	s := &subscriptionRawData{
		PeerInfo: data,
	}
	s.UpdateTime = time.Now()
	subscriptionInfo := header.Get("subscription-userinfo")
	if subscriptionInfo != "" {
		subscriptionInfo = strings.ToLower(subscriptionInfo)
		regTraffic := regexp.MustCompile("upload=(\\d+); download=(\\d+); total=(\\d+)")
		matchTraffic := regTraffic.FindStringSubmatch(subscriptionInfo)
		if len(matchTraffic) == 4 {
			uploadUint64, err := strconv.ParseUint(matchTraffic[1], 10, 64)
			if err == nil {
				s.Upload = uploadUint64
			}
			downloadUint64, err := strconv.ParseUint(matchTraffic[2], 10, 64)
			if err == nil {
				s.Download = downloadUint64
			}
			totalUint64, err := strconv.ParseUint(matchTraffic[3], 10, 64)
			if err == nil {
				s.Total = totalUint64
			}
		}
		regExpire := regexp.MustCompile("expire=(\\d+)")
		matchExpire := regExpire.FindStringSubmatch(subscriptionInfo)
		if len(matchExpire) == 2 {
			expireUint64, err := strconv.ParseUint(matchExpire[1], 10, 64)
			if err == nil {
				s.Expire = time.Unix(int64(expireUint64), 0)
			}
		}
	}

	return s, nil
}

func (p *ProxyProvider) httpRequest(req *http.Request) (http.Header, []byte, error) {
	var (
		ip  netip.Addr
		err error
	)
	if p.options.RequestIP != nil {
		ip = *p.options.RequestIP
	} else {
		ip, err = netip.ParseAddr(req.URL.Hostname())
		if err != nil {
			ips, err := p.query(req.URL.Hostname())
			if err != nil {
				return nil, nil, E.Cause(err, "failed to resolve domain")
			}
			ip = ips[0]
		}
	}
	port := req.URL.Port()
	if port == "" {
		if req.URL.Scheme == "https" {
			port = "443"
		} else if req.URL.Scheme == "http" {
			port = "80"
		}
	}

	var reqTimeout time.Duration
	if p.options.RequestTimeout > 0 {
		reqTimeout = time.Duration(p.options.RequestTimeout)
	} else {
		reqTimeout = requestTimeout
	}

	if p.options.HTTP3 {
		h3Client := &http.Client{
			Transport: &http3.RoundTripper{
				Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
					destinationAddr := M.ParseSocksaddr(net.JoinHostPort(ip.String(), port))
					conn, err := p.dialer.DialContext(ctx, N.NetworkUDP, destinationAddr)
					if err != nil {
						return nil, err
					}
					return quic.DialEarly(ctx, bufio.NewUnbindPacketConn(conn), conn.RemoteAddr(), tlsCfg, cfg)
				},
			},
		}
		reqCtx, reqCancel := context.WithTimeout(p.ctx, reqTimeout)
		defer reqCancel()
		reqWithCtx := req.Clone(context.Background())
		reqWithCtx = reqWithCtx.WithContext(reqCtx)
		resp, err := h3Client.Do(reqWithCtx)
		if err == nil {
			defer resp.Body.Close()
			buf := &bytes.Buffer{}
			_, err = io.Copy(buf, resp.Body)
			if err != nil {
				return nil, nil, err
			}
			return resp.Header, buf.Bytes(), nil
		}
	}

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return p.dialer.DialContext(ctx, network, M.ParseSocksaddr(net.JoinHostPort(ip.String(), port)))
			},
			ForceAttemptHTTP2: true,
		},
	}

	reqCtx, reqCancel := context.WithTimeout(p.ctx, reqTimeout)
	defer reqCancel()
	reqWithCtx := req.Clone(context.Background())
	reqWithCtx = reqWithCtx.WithContext(reqCtx)
	resp, err := client.Do(reqWithCtx)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	buf := &bytes.Buffer{}
	_, err = io.Copy(buf, resp.Body)
	if err != nil {
		return nil, nil, err
	}
	return resp.Header, buf.Bytes(), nil
}
