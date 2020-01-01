package alibp2p

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/binary"
	"errors"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/routing"
	"io"
	"math/big"
	"sync"
	"time"
)

type (
	SimplePacketHead []byte

	Config struct {
		Ctx                                    context.Context
		Homedir                                string
		Port, ConnLow, ConnHi, BootstrapPeriod uint64
		Bootnodes                              []string
		Discover                               bool
		Networkid, MuxPort                     *big.Int

		PrivKey  *ecdsa.PrivateKey
		Loglevel int // 3 INFO, 4 DEBUG, 5 TRACE
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

func ReadSimplePacketHead(r io.Reader) (SimplePacketHead, error) {
	head := make([]byte, 6)
	t, err := r.Read(head)
	if t != 6 || err != nil {
		return nil, err
	}
	return head, nil
}

func NewSimplePacketHead(msgType uint16, data []byte) SimplePacketHead {
	var psize = uint32(len(data))
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, &msgType)
	binary.Write(buf, binary.BigEndian, &psize)
	return buf.Bytes()
}

func (header SimplePacketHead) Decode() (msgType uint16, size uint32, err error) {
	if len(header) != 6 {
		err = errors.New("error_header")
		return
	}
	msgTypeR := bytes.NewReader(header[:2])
	err = binary.Read(msgTypeR, binary.BigEndian, &msgType)
	if err != nil {
		return
	}
	sizeR := bytes.NewReader(header[2:])
	err = binary.Read(sizeR, binary.BigEndian, &size)
	return
}

func (blankValidator) Validate(_ string, _ []byte) error        { return nil }
func (blankValidator) Select(_ string, _ [][]byte) (int, error) { return 0, nil }
