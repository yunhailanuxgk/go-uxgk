package alibp2p

import (
	"context"
	"crypto/ecdsa"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/routing"
	"math/big"
	"sync"
	"time"
)

type (
	Config struct {
		Ctx                                    context.Context
		Homedir                                string
		Port, ConnLow, ConnHi, BootstrapPeriod uint64
		Bootnodes                              []string
		Discover                               bool
		Networkid, MuxPort                     *big.Int

		PrivKey *ecdsa.PrivateKey
	}

	Service struct {
		ctx        context.Context
		homedir    string
		host       host.Host
		router     routing.Routing
		bootnodes  []peer.AddrInfo
		cfg        Config
		notifiee   *network.NotifyBundle
		isDirectFn func(id string) bool
	}
	blankValidator struct{}
	ConnType       int

	asyncFn struct {
		fn   func(context.Context, []interface{})
		args []interface{}
	}
	AsyncRunner struct {
		sync.Mutex
		wg                *sync.WaitGroup
		ctx               context.Context
		counter, min, max int32
		fnCh              chan *asyncFn
		closeCh           chan struct{}
		close             bool
		gc                time.Duration
	}
)

func (blankValidator) Validate(_ string, _ []byte) error        { return nil }
func (blankValidator) Select(_ string, _ [][]byte) (int, error) { return 0, nil }
