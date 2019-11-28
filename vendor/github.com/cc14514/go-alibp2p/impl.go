package alibp2p

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	netmux "github.com/cc14514/go-mux-transport"
	"github.com/libp2p/go-libp2p"
	circuit "github.com/libp2p/go-libp2p-circuit"
	connmgr "github.com/libp2p/go-libp2p-connmgr"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/helpers"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/peerstore"
	"github.com/libp2p/go-libp2p-core/protocol"
	"github.com/libp2p/go-libp2p-core/routing"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	opts "github.com/libp2p/go-libp2p-kad-dht/opts"
	ma "github.com/multiformats/go-multiaddr"
	"golang.org/x/xerrors"
	"io/ioutil"
	"log"
	"strings"
	"sync/atomic"
	"time"
)

func NewService(cfg Config) Alibp2pService {
	log.Println("alibp2p.NewService", cfg)
	var (
		err             error
		router          routing.Routing
		priv            crypto.PrivKey
		bootnodes       []peer.AddrInfo
		connLow, connHi = cfg.ConnLow, cfg.ConnHi
	)
	if connLow == 0 {
		connLow = defConnLow
	}
	if connHi == 0 {
		connHi = defConnHi
	}
	if cfg.PrivKey != nil {
		_p := (*crypto.Secp256k1PrivateKey)(cfg.PrivKey)
		priv = (crypto.PrivKey)(_p)
	} else {
		priv, err = loadid(cfg.Homedir)
	}
	list := make([]ma.Multiaddr, 0)
	listen0, _ := ma.NewMultiaddr(fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", cfg.Port))
	list = append(list, listen0)
	if cfg.MuxPort != nil {
		listen1, _ := ma.NewMultiaddr(fmt.Sprintf("/ip4/0.0.0.0/mux/%d:%d", cfg.MuxPort, cfg.Port))
		list = append(list, listen1)
		netmux.Register(cfg.Ctx, int(cfg.MuxPort.Int64()), int(cfg.Port))
	}
	optlist := []libp2p.Option{
		libp2p.NATPortMap(),
		libp2p.ListenAddrs(list...),
		libp2p.Identity(priv),
		libp2p.EnableAutoRelay(),
		libp2p.EnableRelay(circuit.OptActive, circuit.OptDiscovery, circuit.OptHop),
		libp2p.ConnectionManager(connmgr.NewConnManager(int(connLow), int(connHi), time.Second*30)),
		libp2p.Routing(func(h host.Host) (routing.PeerRouting, error) {
			if router == nil {
				dht, err := dht.New(cfg.Ctx, h,
					opts.Client(false),
					opts.NamespacedValidator(NamespaceDHT, blankValidator{}),
					opts.Protocols(DefaultProtocols...))
				if err != nil {
					panic(xerrors.Errorf("dht : %w", err))
				}
				router = dht
			}
			return router, nil
		}),
	}
	if p, err := cfg.ProtectorOpt(); err == nil {
		optlist = append(optlist, p)
	}
	optlist = append(optlist, cfg.MuxTransportOption())

	host, err := libp2p.New(cfg.Ctx, optlist...)
	if err != nil {
		panic(err)
	}

	hostAddr, err := ma.NewMultiaddr(fmt.Sprintf("/ipfs/%s", host.ID().Pretty()))
	for i, addr := range host.Addrs() {
		full := addr.Encapsulate(hostAddr)
		log.Println(i, "listen on", full)
	}

	if cfg.Bootnodes != nil && len(cfg.Bootnodes) > 0 {
		bootnodes, err = convertPeers(cfg.Bootnodes)
		if err != nil {
			panic(err)
		}
	}

	service := &Service{
		cfg:       cfg,
		ctx:       cfg.Ctx,
		homedir:   cfg.Homedir,
		host:      host,
		router:    router,
		bootnodes: bootnodes,
		notifiee:  new(network.NotifyBundle),
	}

	service.isDirectFn = func(id string) bool {
		direct, _ := service.Conns()
		for _, url := range direct {
			if strings.Contains(url, id) {
				return true
			}
		}
		return false
	}

	return service
}

func (self *Service) ClosePeer(pubkey *ecdsa.PublicKey) error {
	id, err := ECDSAPubEncode(pubkey)
	if err != nil {
		return err
	}
	p, err := peer.IDB58Decode(id)
	if err != nil {
		return err
	}
	return self.host.Network().ClosePeer(p)
}

func (self *Service) SetBootnode(peer ...string) error {
	pi, err := convertPeers(peer)
	self.bootnodes = pi
	return err
}

func (self *Service) Myid() (id string, addrs []string) {
	id = self.host.ID().Pretty()
	addrs = make([]string, 0)
	for _, maddr := range self.host.Addrs() {
		if a := maddr.String(); !strings.Contains(a, "/p2p-circuit") {
			addrs = append(addrs, maddr.String())
		}
	}
	return
}

func (self *Service) SetHandler(pid string, handler StreamHandler) {
	self.host.SetStreamHandler(protocol.ID(pid), func(s network.Stream) {
		defer func() {
			if s != nil {
				go helpers.FullClose(s)
			}
		}()
		conn := s.Conn()
		sid := fmt.Sprintf("session:%s%s", conn.RemoteMultiaddr().String(), conn.LocalMultiaddr().String())
		pk, err := id2pubkey(s.Conn().RemotePeer())
		if err != nil {
			log.Println(err)
			return
		}
		pubkeyToEcdsa(pk)
		if err := handler(sid, pubkeyToEcdsa(pk), s); err != nil {
			log.Println(err)
		}
	})
}

func (self *Service) SetStreamHandler(protoid string, handler func(s network.Stream)) {
	self.host.SetStreamHandler(protocol.ID(protoid), handler)
}

//TODO add by liangc : connMgr protected / unprotected setting
func (self *Service) SendMsgAfterClose(to, protocolID string, msg []byte) error {
	id, s, _, err := self.SendMsg(to, protocolID, msg)
	//self.host.ConnManager().Protect(id, "tmp")
	if s != nil {
		go helpers.FullClose(s)
	}
	if err != nil {
		self.host.Network().ClosePeer(id)
		return err
	}
	//self.host.ConnManager().Unprotect(id, "tmp")
	return nil
}

func (self *Service) Connect(url string) error {
	ipfsaddr, err := ma.NewMultiaddr(url)
	if err != nil {
		return err
	}
	pid, err := ipfsaddr.ValueForProtocol(ma.P_IPFS)
	if err != nil {
		return err
	}
	peerid, err := peer.IDB58Decode(pid)
	if err != nil {
		return err
	}
	targetPeerAddr, _ := ma.NewMultiaddr(fmt.Sprintf("/ipfs/%s", peer.IDB58Encode(peerid)))
	targetAddr := ipfsaddr.Decapsulate(targetPeerAddr)
	return self.host.Connect(self.ctx, peer.AddrInfo{ID: peerid, Addrs: []ma.Multiaddr{targetAddr}})
}

func (self *Service) SendMsg(to, protocolID string, msg []byte) (peer.ID, network.Stream, int, error) {
	peerid, err := peer.IDB58Decode(to)
	if err != nil {
		ipfsaddr, err := ma.NewMultiaddr(to)
		if err != nil {
			log.Println(err)
			return peerid, nil, 0, err
		}

		pid, err := ipfsaddr.ValueForProtocol(ma.P_IPFS)
		if err != nil {
			log.Println(err)
			return peerid, nil, 0, err
		}
		peerid, err = peer.IDB58Decode(pid)
		if err != nil {
			log.Println(err)
			return peerid, nil, 0, err
		}
		targetPeerAddr, _ := ma.NewMultiaddr(fmt.Sprintf("/ipfs/%s", peer.IDB58Encode(peerid)))
		targetAddr := ipfsaddr.Decapsulate(targetPeerAddr)
		relayAddr, _ := ma.NewMultiaddr(fmt.Sprintf("/p2p-circuit/ipfs/%s", peer.IDB58Encode(peerid)))
		raddr := []ma.Multiaddr{relayAddr, targetAddr}
		self.host.Peerstore().AddAddrs(peerid, raddr, peerstore.PermanentAddrTTL)
	} else {
		pi, err := self.router.FindPeer(self.ctx, peerid)
		if err != nil {
			log.Println(err)
			return peerid, nil, 0, err
		}
		self.host.Peerstore().AddAddrs(pi.ID, pi.Addrs, peerstore.PermanentAddrTTL)
	}

	s, err := self.host.NewStream(self.ctx, peerid, protocol.ID(protocolID))
	if err != nil {
		log.Println(err)
		return peerid, nil, 0, err
	}
	var total int
	total, err = s.Write(msg)
	if err != nil {
		log.Println(err)
		return peerid, nil, total, err
	}
	return peerid, s, total, nil
}

func (self *Service) PreConnect(pubkey *ecdsa.PublicKey) error {
	id, err := peer.IDFromPublicKey(ecdsaToPubkey(pubkey))
	if err != nil {
		log.Println("PreConnect-error-1", "id", id.Pretty(), "err", err)
		return err
	}
	pi, err := self.findpeer(id.Pretty())
	if err != nil {
		log.Println("PreConnect-error-2", "id", id.Pretty(), "err", err)
		return err
	}
	ctx := context.WithValue(self.ctx, "nodelay", "true")
	err = connectFn(ctx, self.host, []peer.AddrInfo{pi})
	if err != nil {
		log.Println("PreConnect-error-3", "id", id.Pretty(), "err", err)
		return err
	}
	log.Println("PreConnect-success : protected", "id", id.Pretty())
	self.host.ConnManager().Protect(id, "pre")
	go func(ctx context.Context, id peer.ID) {
		select {
		case <-time.After(peerstore.TempAddrTTL / 4):
			ok := self.host.ConnManager().Unprotect(id, "pre")
			log.Println("PreConnect-expire : unprotect", "id", id.Pretty(), "ok", ok)
		case <-ctx.Done():
		}
	}(ctx, id)
	return nil
}

func (self *Service) OnConnected(t ConnType, preMsg PreMsg, callbackFn ConnectEvent) {
	//self.SetStreamHandler()
	self.notifiee.ConnectedF = func(i network.Network, conn network.Conn) {
		switch t {
		case CONNT_TYPE_DIRECT:
			if !self.isDirectFn(conn.RemotePeer().Pretty()) {
				return
			}
		case CONN_TYPE_RELAY:
			if self.isDirectFn(conn.RemotePeer().Pretty()) {
				return
			}
		case CONN_TYPE_ALL:
		}
		var (
			in     bool
			pk, _  = id2pubkey(conn.RemotePeer())
			sid    = fmt.Sprintf("session:%s%s", conn.RemoteMultiaddr().String(), conn.LocalMultiaddr().String())
			pubkey = pubkeyToEcdsa(pk)
			preRtn []byte
		)
		switch conn.Stat().Direction {
		case network.DirInbound:
			in = true
		case network.DirOutbound:
			in = false
		}
		// 连出去的，并且 preMsg 有值，就给对方发消息
		if !in && preMsg != nil {
			proto, pkg := preMsg()
			resp, err := self.Request(conn.RemotePeer().Pretty(), proto, pkg)
			if err == nil {
				preRtn = resp
			} else {
				preRtn = []byte(err.Error())
			}
		}
		callbackFn(in, sid, pubkey, preRtn)
	}
}

func (self *Service) Request(to, proto string, pkg []byte) ([]byte, error) {
	_, s, _, err := self.SendMsg(to, proto, pkg)
	if err == nil {
		s.SetDeadline(time.Now().Add(10 * time.Second))
		defer helpers.FullClose(s)
		buf, err := ioutil.ReadAll(s)
		if err == nil {
			return buf, nil
		}
	}
	return nil, err
}

func (self *Service) OnDisconnected(callback DisconnectEvent) {
	self.notifiee.DisconnectedF = func(i network.Network, conn network.Conn) {
		pk, _ := id2pubkey(conn.RemotePeer())
		for _, c := range i.Conns() {
			c.RemotePeer()
		}
		sid := fmt.Sprintf("session:%s%s", conn.RemoteMultiaddr().String(), conn.LocalMultiaddr().String())
		callback(sid, pubkeyToEcdsa(pk))
	}
}

func (self *Service) Start() {
	self.host.Network().Notify(self.notifiee)
	if self.cfg.Discover {
		self.bootstrap()
	}
}

func (self *Service) Table() map[string][]string {
	r := make(map[string][]string, 0)
	for _, p := range self.host.Peerstore().Peers() {
		a := make([]string, 0)
		pi := self.host.Peerstore().PeerInfo(p)
		for _, addr := range pi.Addrs {
			a = append(a, addr.String())
		}
		r[p.Pretty()] = a
	}
	return r
}

func (self *Service) GetSession(id string) (session string, inbound bool, err error) {
	err = fmt.Errorf("getsession fail : %s not found.", id)
	for _, conn := range self.host.Network().Conns() {
		if strings.Contains(id, conn.RemotePeer().Pretty()) {
			switch conn.Stat().Direction {
			case network.DirInbound:
				inbound = true
			case network.DirOutbound:
				inbound = false
			}
			session = fmt.Sprintf("session:%s%s", conn.RemoteMultiaddr().String(), conn.LocalMultiaddr().String())
			err = nil
		}
	}
	return session, inbound, err
}

func (self *Service) Conns() (direct []string, relay []string) {
	direct, relay = make([]string, 0), make([]string, 0)
	for _, c := range self.host.Network().Conns() {
		remoteaddr, _ := ma.NewMultiaddr(fmt.Sprintf("/ipfs/%s", c.RemotePeer().Pretty()))
		maddr := c.RemoteMultiaddr().Encapsulate(remoteaddr)
		taddr, _ := maddr.MarshalText()
		if strings.Contains(string(taddr), "p2p-circuit") {
			relay = append(relay, string(taddr))
		} else {
			direct = append(direct, string(taddr))
		}
	}
	return direct, relay
}

func (self *Service) Peers() (direct []string, relay map[string][]string, total int) {
	direct, relay, total = make([]string, 0), make(map[string][]string), 0
	dl, rl := self.Conns()
	for _, d := range dl {
		direct = append(direct, strings.Split(d, "/ipfs/")[1])
		total += 1
	}
	for _, r := range rl {
		arr := strings.Split(r, "/p2p-circuit")
		f, t := arr[0], arr[1]

		rarr, ok := relay[strings.Split(f, "/ipfs/")[1]]
		if !ok {
			rarr = make([]string, 0)
		}
		rarr = append(rarr, strings.Split(t, "/ipfs/")[1])
		relay[strings.Split(f, "/ipfs/")[1]] = rarr
		total += 1
	}
	return direct, relay, total
}

func (self *Service) PutPeerMeta(id, key string, v interface{}) error {
	p, err := peer.IDB58Decode(id)
	if err != nil {
		return err
	}
	return self.host.Peerstore().Put(p, key, v)
}

func (self *Service) GetPeerMeta(id, key string) (interface{}, error) {
	p, err := peer.IDB58Decode(id)
	if err != nil {
		return nil, err
	}
	return self.host.Peerstore().Get(p, key)
}

func (self *Service) Findpeer(id string) ([]string, error) {
	pi, err := self.findpeer(id)
	if err != nil {
		return nil, err
	}
	addrs := make([]string, 0)
	for _, addr := range pi.Addrs {
		if a := addr.String(); !strings.Contains(a, "/p2p-circuit") {
			addrs = append(addrs, addr.String())
		}
	}
	return addrs, nil
}

func (self *Service) findpeer(id string) (peer.AddrInfo, error) {
	peerid, err := peer.IDB58Decode(id)
	if err != nil {
		return peer.AddrInfo{}, err
	}
	pi, err := self.router.FindPeer(self.ctx, peerid)
	if err != nil {
		return pi, err
	}
	return pi, nil
}

func (self *Service) Put(k string, v []byte) error {
	return self.router.PutValue(self.ctx, fmt.Sprintf("/%s/%s", NamespaceDHT, k), v)
}

func (self *Service) Get(k string) ([]byte, error) {
	return self.router.GetValue(self.ctx, fmt.Sprintf("/%s/%s", NamespaceDHT, k))
}

func (self *Service) BootstrapOnce() error {
	err := connectFn(self.ctx, self.host, self.bootnodes)
	if err != nil {
		log.Println("bootstrap-once-conn-error", "err", err)
	}
	err = self.router.(*dht.IpfsDHT).BootstrapOnce(self.ctx, dht.DefaultBootstrapConfig)
	if err != nil {
		log.Println("bootstrap-once-query-error", "err", err)
	}
	return err
}

func (self *Service) bootstrap() error {
	period := uint64(5)
	if self.cfg.BootstrapPeriod > period {
		period = self.cfg.BootstrapPeriod
	}
	log.Println("host-addrs", self.host.Addrs())
	log.Println("host-network-listen", self.host.Network().ListenAddresses())
	log.Println("host-peerinfo", self.host.Peerstore().PeerInfo(self.host.ID()))
	go func() {
		log.Println("loopboot-start", "period", period)
		if atomic.CompareAndSwapInt32(&loopboot, 0, 1) {
			defer func() {
				atomic.StoreInt32(&loopboot, 0)
				atomic.StoreInt32(&loopbootstrap, 0)
			}()
			timer := time.NewTimer(time.Second)
			for {
				select {
				case <-self.ctx.Done():
					return
				case <-timer.C:
					if self.bootnodes != nil && len(self.host.Network().Conns()) < len(self.bootnodes) {
						// 在 peerstore 中随机找至多 5 个节点尝试连接
						var (
							limit  = 3
							others = self.peersWithoutBootnodes()
							total  = len(others)
						)
						log.Println("bootstrap looping")
						err := connectFn(self.ctx, self.host, self.bootnodes)
						if err == nil {
							log.Println("bootstrap success")
							if atomic.CompareAndSwapInt32(&loopbootstrap, 0, 1) {
								log.Println("Bootstrap the host")
								err = self.router.Bootstrap(self.ctx)
								if err != nil {
									log.Println("bootstrap-error", "err", err)
								}
							} else {
								log.Println("Reconnected and bootstrap the host once")
								self.BootstrapOnce()
							}
						} else if total > 0 {
							if total < limit {
								limit = total
							}
							tasks := randPeers(others, limit)
							err := connectFn(self.ctx, self.host, tasks)
							log.Println("bootstrap fail try to conn others -->", "err", err, "total", total, "limit", limit, "tasks", tasks)
						}
					}
				}
				timer.Reset(time.Duration(period) * time.Second)
			}
		}
		log.Println("loopboot-end")
	}()
	return nil
}

func (self *Service) peersWithoutBootnodes() []peer.AddrInfo {
	var (
		result  = make([]peer.AddrInfo, 0)
		bootmap = make(map[string]interface{})
	)
	for _, b := range self.bootnodes {
		bootmap[b.ID.Pretty()] = struct{}{}
	}

	for _, p := range self.host.Peerstore().Peers() {
		if _, ok := bootmap[p.Pretty()]; ok {
			continue
		}
		if p.Pretty() == self.host.ID().Pretty() {
			continue
		}
		if pi := self.host.Peerstore().PeerInfo(p); pi.Addrs != nil && len(pi.Addrs) > 0 {
			result = append(result, pi)
		}
	}

	return result
}
