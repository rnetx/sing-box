//go:build with_randomaddr

package outbound

import (
	"context"
	"math/big"
	"math/rand"
	"net"
	"net/netip"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var _ adapter.Outbound = (*RandomAddr)(nil)

type RandomAddr struct {
	myOutboundAdapter
	ctx       context.Context
	dialer    N.Dialer
	addresses []option.RandomAddress
	udp       bool
}

func NewRandomAddr(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.RandomAddrOutboundOptions) (adapter.Outbound, error) {
	if len(options.Addresses) == 0 {
		return nil, E.New("no addresses")
	}
	outboundDialer, err := dialer.New(router, options.DialerOptions)
	if err != nil {
		return nil, err
	}
	r := &RandomAddr{
		myOutboundAdapter: myOutboundAdapter{
			protocol:     C.TypeRandomAddr,
			router:       router,
			logger:       logger,
			tag:          tag,
			dependencies: withDialerDependency(options.DialerOptions),
		},
		ctx:       ctx,
		dialer:    outboundDialer,
		addresses: options.Addresses,
		udp:       options.UDP,
	}
	return r, nil
}

func (r *RandomAddr) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	r.rewriteSocksAddr(&destination)
	return r.dialer.DialContext(ctx, network, destination)
}

func (r *RandomAddr) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if r.udp {
		r.rewriteSocksAddr(&destination)
	}
	return r.dialer.ListenPacket(ctx, destination)
}

func (r *RandomAddr) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	return NewConnection(ctx, r, conn, metadata)
}

func (r *RandomAddr) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	return NewPacketConnection(ctx, r, conn, metadata)
}

func (r *RandomAddr) rewriteSocksAddr(destination *M.Socksaddr) {
	address := r.addresses[random().Int31n(int32(len(r.addresses)))]
	if address.Port != nil {
		destination.Port = *address.Port
	}
	if address.IP != nil {
		prefix := netip.Prefix(*address.IP)
		bits := prefix.Bits()
		if bits == 32 || bits == 128 {
			destination.Addr = prefix.Addr()
		} else {
			destination.Addr = randomAddrFromPrefix(prefix)
		}
	}
}

func random() *rand.Rand {
	return rand.New(rand.NewSource(time.Now().UnixNano()))
}

func randomAddrFromPrefix(prefix netip.Prefix) netip.Addr {
	startN := big.NewInt(0).SetBytes(prefix.Addr().AsSlice())
	var bits int
	if prefix.Addr().Is4() {
		bits = 5
	} else {
		bits = 7
	}
	bt := big.NewInt(0).Exp(big.NewInt(2), big.NewInt(1<<bits-int64(prefix.Bits())), nil)
	bt.Sub(bt, big.NewInt(2))
	n := big.NewInt(0).Rand(random(), bt)
	n.Add(n, startN)
	newAddr, _ := netip.AddrFromSlice(n.Bytes())
	return newAddr
}
