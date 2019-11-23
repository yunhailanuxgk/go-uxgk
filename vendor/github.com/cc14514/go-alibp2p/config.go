package alibp2p

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	lru "github.com/hashicorp/golang-lru"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-core/protocol"
	mplex "github.com/libp2p/go-libp2p-mplex"
	apnet "github.com/libp2p/go-libp2p-pnet"
	yamux "github.com/libp2p/go-libp2p-yamux"
	"io/ioutil"
	"strings"
	"time"
)

const (
	ProtocolDHT           protocol.ID = "/pdx/kad/1.0.0"
	NamespaceDHT                      = "cc14514"
	defConnLow, defConnHi             = 50, 500
	PSK_TMP                           = `/key/swarm/psk/1.0.0/
/base16/
%s`
)

const (
	CONNT_TYPE_DIRECT ConnType = iota
	CONN_TYPE_RELAY
	CONN_TYPE_ALL
)

var (
	pubkeyCache, _          = lru.New(10000)
	DefaultProtocols        = []protocol.ID{ProtocolDHT}
	loopboot, loopbootstrap int32
)

func (cfg Config) ProtectorOpt() (libp2p.Option, error) {
	if cfg.Networkid != nil {
		s := sha256.New()
		s.Write(cfg.Networkid.Bytes())
		k := s.Sum(nil)
		key := fmt.Sprintf(PSK_TMP, hex.EncodeToString(k))
		r := strings.NewReader(key)
		p, err := apnet.NewProtector(r)
		if err != nil {
			return nil, err
		}
		return libp2p.PrivateNetwork(p), nil
	}
	return nil, errors.New("disable psk")
}

/*

// DefaultConfig is used to return a default configuration
func DefaultConfig() *Config {
	return &Config{
		AcceptBacklog:          256,
		EnableKeepAlive:        true,
		KeepAliveInterval:      30 * time.Second,
		ConnectionWriteTimeout: 10 * time.Second,
		MaxStreamWindowSize:    initialStreamWindow,
		LogOutput:              os.Stderr,
		ReadBufSize:            4096,
		MaxMessageSize:         64 * 1024, // Means 64KiB/10s = 52kbps minimum speed.
		WriteCoalesceDelay:     100 * time.Microsecond,
	}
}
*/
func (cfg Config) MuxTransportOption() libp2p.Option {
	ymxtpt := &yamux.Transport{
		AcceptBacklog:          256,
		EnableKeepAlive:        true,
		KeepAliveInterval:      45 * time.Second,
		ConnectionWriteTimeout: 45 * time.Second,
		MaxStreamWindowSize:    uint32(256 * 1024),
		LogOutput:              ioutil.Discard,
		//LogOutput:              os.Stderr,
		ReadBufSize:        4096,
		MaxMessageSize:     128 * 1024, // Means 128KiB/10s
		WriteCoalesceDelay: 100 * time.Microsecond,
	}
	return libp2p.ChainOptions(
		libp2p.Muxer("/yamux/1.0.0", ymxtpt),
		libp2p.Muxer("/mplex/6.7.0", mplex.DefaultTransport),
	)

}
