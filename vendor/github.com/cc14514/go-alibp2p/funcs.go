package alibp2p

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	pool "github.com/libp2p/go-buffer-pool"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/peerstore"
	ma "github.com/multiformats/go-multiaddr"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"path"
	"sync"
	"sync/atomic"
	"time"
)

func (f *asyncFn) apply(ctx context.Context) {
	f.fn(ctx, f.args)
}

func NewAsyncRunner(ctx context.Context, min, max int32) *AsyncRunner {
	wg := new(sync.WaitGroup)
	o := &AsyncRunner{
		ctx:     ctx,
		wg:      wg,
		counter: 0,
		min:     min,
		max:     max,
		fnCh:    make(chan *asyncFn),
		closeCh: make(chan struct{}),
		gc:      5 * time.Second,
	}
	wg.Add(1)
	go func() {
		select {
		case <-ctx.Done():
		case <-o.closeCh:
		}
		wg.Done()
	}()
	return o
}

func (a *AsyncRunner) Size() int32 {
	return atomic.LoadInt32(&a.counter)
}

func (a *AsyncRunner) WaitClose() {
	a.close = true
	a.wg.Wait()
}

func (a *AsyncRunner) Wait() {
	a.wg.Wait()
}

func (a *AsyncRunner) spawn(tn int32, fn func(ctx context.Context, args []interface{}), args ...interface{}) {
	a.wg.Add(1)
	go func(tn int32) {
		defer a.wg.Done()
		timer := time.NewTimer(a.gc)
		for {
			select {
			case fn := <-a.fnCh:
				fn.apply(context.WithValue(a.ctx, "tn", tn))
			case <-a.ctx.Done():
				atomic.AddInt32(&a.counter, -1)
				return
			case <-timer.C:
				if func() bool {
					a.Lock()
					defer a.Unlock()
					if c := atomic.LoadInt32(&a.counter); c > a.min || a.close {
						c = atomic.AddInt32(&a.counter, -1)
						//fmt.Println("<--gc--", "tn", tn, a.close, "min", a.min, "counter", c)
						if c == 0 {
							close(a.closeCh)
						}
						return true
					}
					return false
				}() {
					return
				}
			}
			timer.Reset(a.gc)
		}
	}(tn)
}

func (a *AsyncRunner) Apply(fn func(ctx context.Context, args []interface{}), args ...interface{}) {
	select {
	case a.fnCh <- &asyncFn{fn, args}:
	default:
		//if tn := atomic.AddInt32(&a.counter, 1); tn <= a.max {
		a.Lock()
		tn := atomic.LoadInt32(&a.counter) + 1
		if tn <= a.max {
			atomic.AddInt32(&a.counter, 1)
			a.spawn(tn, fn, args)
		}
		a.Unlock()
		a.fnCh <- &asyncFn{fn, args}
	}
}

// private funcs
var (
	loadid = func(homedir string) (crypto.PrivKey, error) {
		keypath := path.Join(homedir, "p2p.id")
		log.Println("keypath", keypath)
		buff1, err := ioutil.ReadFile(keypath)
		if err != nil {
			err := os.MkdirAll(homedir, 0755)
			if err != nil {
				panic(err)
			}
			priv, _, err := crypto.GenerateSecp256k1Key(rand.Reader)
			k0 := priv.(*crypto.Secp256k1PrivateKey)
			k1 := (*ecdsa.PrivateKey)(k0)
			arr := [3]*big.Int{k1.X, k1.Y, k1.D}
			buff, _ := json.Marshal(arr)
			s0 := hex.EncodeToString(buff)
			err = ioutil.WriteFile(keypath, []byte(s0), 0755)
			if err != nil {
				panic(err)
			}
			return priv, err
		}
		var arr1 = new([3]*big.Int)
		buff, _ := hex.DecodeString(string(buff1))
		err = json.Unmarshal(buff, arr1)
		if err != nil {
			panic(err)
		}
		priv1 := new(ecdsa.PrivateKey)
		priv1.X, priv1.Y, priv1.D, priv1.Curve = arr1[0], arr1[1], arr1[2], btcec.S256()
		priv2 := (*crypto.Secp256k1PrivateKey)(priv1)
		priv3 := (crypto.PrivKey)(priv2)
		return priv3, err
	}

	connectFn = func(ctx context.Context, ph host.Host, peers []peer.AddrInfo) error {
		if len(peers) < 1 {
			return errors.New("not enough peers to connect")
		}

		errs := make(chan error, len(peers))
		var wg sync.WaitGroup
		for _, p := range peers {
			if ph.ID() == p.ID {
				continue
			}
			wg.Add(1)
			go func(p peer.AddrInfo) {
				defer wg.Done()
				log.Printf("from %s connecting to %s : %v", ph.ID().Pretty(), p.ID, p.Addrs)
				ph.Peerstore().AddAddrs(p.ID, p.Addrs, peerstore.PermanentAddrTTL)
				if err := ph.Connect(ctx, p); err != nil {
					//log.Println("connect failed", p.ID)
					//log.Printf("failed to connect with %v: %s", p.ID, err)
					errs <- err
					return
				}
				log.Println("connect success :", p.ID.Pretty())
			}(p)
		}
		wg.Wait()
		close(errs)
		count := 0
		var err error
		for err = range errs {
			if err != nil {
				count++
			}
		}
		if count == len(peers) {
			return fmt.Errorf("failed to connect. %s", err)
		}
		return nil
	}

	convertPeers = func(peers []string) ([]peer.AddrInfo, error) {
		pinfos := make([]peer.AddrInfo, len(peers))
		for i, addr := range peers {
			maddr := ma.StringCast(addr)
			p, err := peer.AddrInfoFromP2pAddr(maddr)
			if err != nil {
				log.Println(err)
				return nil, err
			}
			pinfos[i] = *p
		}
		return pinfos, nil
	}

	pubkeyToEcdsa = func(pk crypto.PubKey) *ecdsa.PublicKey {
		k0 := pk.(*crypto.Secp256k1PublicKey)
		pubkey := (*ecdsa.PublicKey)(k0)
		return pubkey
	}
	ecdsaToPubkey = func(pk *ecdsa.PublicKey) crypto.PubKey {
		k0 := (*crypto.Secp256k1PublicKey)(pk)
		return k0
	}
	id2pubkey = func(id peer.ID) (crypto.PubKey, error) {
		v, ok := pubkeyCache.Get(id)
		if ok {
			return v.(crypto.PubKey), nil
		}
		k, err := id.ExtractPublicKey()
		if err != nil {
			return nil, err
		}
		pubkeyCache.Add(id, k)
		return k, nil
	}
	randPeers = func(others []peer.AddrInfo, limit int) []peer.AddrInfo {
		_, randk, _ := crypto.GenerateRSAKeyPair(1024, rand.Reader)
		rnBytes, _ := randk.Bytes()
		n := new(big.Int).Mod(new(big.Int).SetBytes(rnBytes), big.NewInt(int64(len(others)))).Int64()
		others = append(others[n:], others[:n]...)
		others = others[:limit]
		return others
	}
)

// public funcs
var (
	ECDSAPubEncode = func(pk *ecdsa.PublicKey) (string, error) {
		id, err := peer.IDFromPublicKey(ecdsaToPubkey(pk))
		return id.Pretty(), err
	}
	ECDSAPubDecode = func(pk string) (*ecdsa.PublicKey, error) {
		id, err := peer.IDB58Decode(pk)
		if err != nil {
			return nil, err
		}
		pub, err := id2pubkey(id)
		if err != nil {
			return nil, err
		}
		return pubkeyToEcdsa(pub), nil
	}

	GetBuf = func(size int) []byte {
		return pool.Get(size)
	}
	PutBuf = func(buf []byte) {
		pool.Put(buf)
	}
	Spawn = func(size int, fn func(int)) *sync.WaitGroup {
		wg := new(sync.WaitGroup)
		for i := 0; i < size; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				fn(i)
			}()
		}
		return wg
	}
)
