//go:build with_proxyprovider

package proxyprovider

import (
	"bytes"
	"context"
	"encoding/gob"
	"encoding/hex"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/proxyprovider/proxy"
	dns "github.com/sagernet/sing-dns"
	N "github.com/sagernet/sing/common/network"
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
	subscriptionRawData     subscriptionRawData
	subscriptionRawDataLock sync.RWMutex
	//
	peerList []proxy.Proxy
	//
	updateLock sync.Mutex
}

type SubScribeInfo struct {
	Upload     uint64
	Download   uint64
	Total      uint64
	Expire     time.Time
	UpdateTime time.Time
}

type subscriptionRawData struct {
	PeerInfo []byte
	SubScribeInfo
}

func (s *subscriptionRawData) encode() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := gob.NewEncoder(buf).Encode(s)
	if err != nil {
		return nil, err
	}
	hexData := make([]byte, hex.EncodedLen(buf.Len()))
	hex.Encode(hexData, buf.Bytes())
	return hexData, nil
}

func (s *subscriptionRawData) decode(data []byte) error {
	data = bytes.TrimSpace(data)
	hexDecData := make([]byte, hex.DecodedLen(len(data)))
	_, err := hex.Decode(hexDecData, data)
	if err != nil {
		return err
	}
	var _s subscriptionRawData
	err = gob.NewDecoder(bytes.NewReader(hexDecData)).Decode(&_s)
	if err != nil {
		return err
	}
	*s = _s
	return nil
}

func (s *SubScribeInfo) GetUpload() uint64 {
	return s.Upload
}

func (s *SubScribeInfo) GetDownload() uint64 {
	return s.Download
}

func (s *SubScribeInfo) GetTotal() uint64 {
	return s.Total
}

func (s *SubScribeInfo) GetExpire() time.Time {
	return s.Expire
}
