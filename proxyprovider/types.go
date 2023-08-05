//go:build with_proxyprovider

package proxyprovider

import (
	"bytes"
	"context"
	"encoding/gob"
	"encoding/hex"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/proxyprovider/proxy"
	dns "github.com/sagernet/sing-dns"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"

	"gopkg.in/yaml.v3"
)

type ProxyProvider struct {
	tag        string
	ctx        context.Context
	router     adapter.Router
	logFactory log.Factory
	logger     log.Logger
	options    option.ProxyProviderOptions
	//
	dialer       N.Dialer
	dnsTransport dns.Transport
	//
	subscriptionData atomic.Pointer[SubscriptionData]
	//
	peerList atomic.Pointer[[]proxy.Proxy]
	//
	updateLock sync.Mutex
}

type SubscriptionInfo struct {
	Upload     uint64
	Download   uint64
	Total      uint64
	Expire     time.Time
	UpdateTime time.Time
}

func (s *SubscriptionInfo) GetUpload() uint64 {
	return s.Upload
}

func (s *SubscriptionInfo) GetDownload() uint64 {
	return s.Download
}

func (s *SubscriptionInfo) GetTotal() uint64 {
	return s.Total
}

func (s *SubscriptionInfo) GetExpire() time.Time {
	return s.Expire
}

type SubscriptionData struct {
	PeerInfo []byte
	PeerList []proxy.ProxyClashOptions
	SubscriptionInfo
}

type _SubscriptionData struct {
	PeerInfo []byte
	SubscriptionInfo
}

func (s *SubscriptionData) encode() ([]byte, error) {
	buf := new(bytes.Buffer)
	_s := _SubscriptionData{
		PeerInfo:         s.PeerInfo,
		SubscriptionInfo: s.SubscriptionInfo,
	}
	err := gob.NewEncoder(buf).Encode(_s)
	if err != nil {
		return nil, err
	}
	hexData := make([]byte, hex.EncodedLen(buf.Len()))
	hex.Encode(hexData, buf.Bytes())
	return hexData, nil
}

func (s *SubscriptionData) decode(data []byte) error {
	data = bytes.TrimSpace(data)
	hexDecData := make([]byte, hex.DecodedLen(len(data)))
	_, err := hex.Decode(hexDecData, data)
	if err != nil {
		return err
	}
	var _s _SubscriptionData
	err = gob.NewDecoder(bytes.NewReader(hexDecData)).Decode(&_s)
	if err != nil {
		return err
	}
	*s = SubscriptionData{
		PeerInfo:         _s.PeerInfo,
		SubscriptionInfo: _s.SubscriptionInfo,
	}
	return nil
}

func (s *SubscriptionData) parse() error {
	var clashConfig proxy.ClashConfig
	err := yaml.Unmarshal(s.PeerInfo, &clashConfig)
	if err != nil {
		return err
	}
	proxies := make([]proxy.Proxy, 0)
	for _, proxyConfig := range clashConfig.Proxies {
		px, err := proxyConfig.ToProxy()
		if err != nil {
			return E.Cause(err, "failed to parse proxy")
		}
		proxies = append(proxies, px)
	}
	s.PeerList = clashConfig.Proxies
	return nil
}
