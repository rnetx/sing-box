//go:build with_proxyprovider

package proxyprovider

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
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
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const requestTimeout = 10 * time.Second

func (p *ProxyProvider) SubScribeAndParse() error {
	var cacheData *SubscriptionData
	if p.options.CacheFile != "" {
		var cacheTime time.Time
		var cacheErr error
		cacheData, cacheTime, cacheErr = readFromCache(p.options.CacheFile)
		if cacheErr == nil {
			if p.options.ForceUpdate == 0 || time.Since(cacheTime) < time.Duration(p.options.ForceUpdate) {
				p.subscriptionData.Store(cacheData)
				return nil
			}
		}
	}
	reqData, err := p.request()
	if err != nil {
		if cacheData != nil {
			if p.logger != nil {
				p.logger.Warn("failed to update proxy provider, use cache, err: ", err)
			}
			p.subscriptionData.Store(cacheData)
			return nil
		}
		return E.Cause(err, "failed to update proxy provider")
	}
	if p.options.CacheFile != "" {
		err := writeToCache(p.options.CacheFile, reqData)
		if err != nil {
			return err
		}
	}
	p.subscriptionData.Store(reqData)
	return nil
}

func (p *ProxyProvider) ForceSubScribeToCache() error {
	if p.options.CacheFile == "" {
		return E.New("no cache file found")
	}
	if !p.updateLock.TryLock() {
		return E.New("updating...")
	}
	defer p.updateLock.Unlock()
	reqData, err := p.request()
	if err != nil {
		return E.Cause(err, "failed to update proxy provider")
	}
	err = writeToCache(p.options.CacheFile, reqData)
	if err != nil {
		return err
	}
	p.subscriptionData.Store(reqData)
	return nil
}

func readFromCache(cacheFile string) (*SubscriptionData, time.Time, error) {
	file, err := os.Open(cacheFile)
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
	var s SubscriptionData
	err = s.decode(data)
	if err != nil {
		return nil, time.Time{}, err
	}
	err = s.parse()
	if err != nil {
		return nil, time.Time{}, err
	}
	return &s, fileInfo.ModTime(), nil
}

func writeToCache(cacheFile string, subscriptionData *SubscriptionData) error {
	if cacheFile != "" {
		data, err := subscriptionData.encode()
		if err != nil {
			return err
		}
		return os.WriteFile(cacheFile, data, 0o644)
	}

	return nil
}

func (p *ProxyProvider) request() (*SubscriptionData, error) {
	req, err := http.NewRequest(http.MethodGet, p.options.URL, nil)
	if err != nil {
		return nil, E.Cause(err, "failed to create http request")
	}
	req.Header.Set("User-Agent", "clash")
	header, data, err := p.httpRequest(req)
	if err != nil {
		return nil, E.Cause(err, "failed to request")
	}
	s := &SubscriptionData{
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
	err = s.parse()
	if err != nil {
		return nil, E.Cause(err, "failed to parse subscription data")
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
			if resp.StatusCode != http.StatusOK {
				return nil, nil, fmt.Errorf("http status code: %d", resp.StatusCode)
			}
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
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("http status code: %d", resp.StatusCode)
	}
	defer resp.Body.Close()
	buf := &bytes.Buffer{}
	_, err = io.Copy(buf, resp.Body)
	if err != nil {
		return nil, nil, err
	}
	return resp.Header, buf.Bytes(), nil
}
