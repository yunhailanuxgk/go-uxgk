package p2p

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/cc14514/go-alibp2p"
	"github.com/yunhailanuxgk/go-uxgk/event"
	"github.com/yunhailanuxgk/go-uxgk/log"
	"github.com/yunhailanuxgk/go-uxgk/p2p/discover"
	"github.com/yunhailanuxgk/go-uxgk/rlp"
	"io"
	"io/ioutil"
	"math/big"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	pingpid          = "/ping/1.0.0"
	premsgpid        = "/premsg/1.0.0"
	msgpid           = "/msg/1.0.0"
	mailboxpid       = "/mailbox/1.0.0"
	senderpool       = 1024
	msgCache         = 16
	setupRetryPeriod = 60 // sec
	bootstrapPeriod  = 30 // sec
	RAWMSG           = 0xffffffff
)

const (
	INBOUND  connType = "inbound"
	OUTBOUND connType = "outbound"
	EMPTY    connType = ""
)

const (
	DELPEER_UNLINK  = "unlink"
	DELPEER_DISCONN = "onDisconnected"
)

const (
	setup  connBehaviour = 0x01 // 接受 连接请求
	ignore connBehaviour = 0x02 // 拒绝 连接请求
	relink connBehaviour = 0x03 // 重新 建立信任
	unlink connBehaviour = 0x04 // 解除 信任关系
)

func (b connBehaviour) Bytes() []byte {
	return []byte{byte(b)}
}

type (
	connType      string
	connBehaviour byte
	writeMsg      struct {
		to      string
		data    []byte
		msgType uint64
	}
	Alibp2p struct {
		unlinkEvent                       event.Feed
		started                           int32
		maxpeers                          int
		srv                               *Server
		p2pservice                        alibp2p.Alibp2pService
		msgWriter                         chan writeMsg
		stop                              chan struct{}
		peerCounter                       *peerCounter
		asyncRunner                       *alibp2p.AsyncRunner
		packetFilter                      func(*ecdsa.PublicKey, uint16, uint32) error
		msgReaders, retryList, allowPeers *sync.Map
	}
	alibp2pTransport struct {
		pubkey     *ecdsa.PublicKey
		sessionKey string
		service    *Alibp2p
		unlinkCh   chan string
		unlinkSub  event.Subscription
	}
	peerCounter struct {
		counter map[string]map[string]string
		lock    *sync.RWMutex
	}

	qmsg struct {
		Code       uint64
		Size       uint32 // size of the paylod
		ReceivedAt uint64
		Payload    []byte
	}
)


var (
	alibp2pMailboxEvent event.Feed

	msgToBytesFn = func(msg Msg) ([]byte, error) {
		data, err := ioutil.ReadAll(msg.Payload)
		//log.Debug("msgToBytesFn", "msgCode", msg.Code, "msgSize", msg.Size)
		if err != nil {
			log.Error("msgToBytesFn-error", "err", err)
			return nil, err
		}
		qm := &qmsg{
			Code:       msg.Code,
			Size:       msg.Size,
			ReceivedAt: uint64(time.Now().Unix()),
			Payload:    data,
		}
		dang, err := rlp.EncodeToBytes(qm)
		if err != nil {
			return nil, err
		}
		return dang, nil
	}
	bytesToMsgFn = func(data []byte) (Msg, error) {
		qm := new(qmsg)
		err := rlp.DecodeBytes(data, qm)
		if err != nil {
			log.Error("bytesToMsgFn_error : unknow msg will return rawmsg", "err", err)
			msg := Msg{}
			if len(data) > 0 {
				msg = Msg{
					Code:       RAWMSG,
					Size:       uint32(len(data)),
					ReceivedAt: time.Unix(int64(qm.ReceivedAt), 0),
					Payload:    bytes.NewReader(data),
				}
				log.Warn("bytesToMsgFn-raw-msg", "len", len(data), "data", data)
				err = nil
			}
			return msg, err
		} else {
			//log.Debug("bytesToMsgFn", "msgCode", qm.Code, "msgSize", qm.Size)
			msg := Msg{
				Code:       qm.Code,
				Size:       qm.Size,
				ReceivedAt: time.Unix(int64(qm.ReceivedAt), 0),
				Payload:    bytes.NewReader(qm.Payload),
			}
			return msg, nil
		}
	}
)

func newPeerCounter() *peerCounter {
	return &peerCounter{make(map[string]map[string]string), new(sync.RWMutex)}
}

func (self *peerCounter) total(condition connType) int {
	self.lock.RLock()
	defer self.lock.RUnlock()
	total := 0
	for _, sm := range self.counter {
		for _, state := range sm {
			if condition == EMPTY && state != "" {
				total++
				break
			} else if condition != EMPTY && state == string(condition) {
				total++
				break
			}
		}
	}
	log.Trace("peerCounter-total", "condition", condition, "counter", len(self.counter))
	return total
}

func (self *peerCounter) del(id, session string, drop bool) {
	self.lock.Lock()
	defer self.lock.Unlock()
	sm, ok := self.counter[id]
	if drop {
		log.Trace("peerCounter-drop", "id", id, "map", sm)
		delete(self.counter, id)
	} else {
		log.Trace("peerCounter-del", "id", id, "session", session, "map", sm)
		if ok {
			delete(sm, session)
		}
		if len(sm) == 0 {
			delete(self.counter, id)
		}
	}
}

func (self *peerCounter) has(id string) bool {
	self.lock.RLock()
	defer self.lock.RUnlock()
	_, ok := self.counter[id]
	return ok
}

func (self *peerCounter) set(id, session, state string) {
	self.lock.Lock()
	defer self.lock.Unlock()
	sm, ok := self.counter[id]
	if !ok {
		sm = make(map[string]string)
		self.counter[id] = sm
	}
	sm[session] = state
	log.Trace("peerCounter-set", "id", id, "state", state, "session", session, "map", sm)
}

func (self *peerCounter) add(id, session string) {
	self.lock.Lock()
	defer self.lock.Unlock()
	sm, ok := self.counter[id]
	if !ok {
		sm = make(map[string]string)
		self.counter[id] = sm
	}
	sm[session] = ""
	log.Trace("peerCounter-add", "id", id, "session", session, "map", sm)
}

func (self *peerCounter) cmp(i int, condition connType) int {
	total := self.total(condition)
	self.lock.RLock()
	defer self.lock.RUnlock()
	log.Trace("peerCounter-cmp", "input", i, "total", total)
	if total > i {
		return 1
	} else if total < i {
		return -1
	}
	return 0
}

//var i int32

func newAlibp2pTransport2(pubkey *ecdsa.PublicKey, sessionKey string, service *Alibp2p) transport {
	unlinkCh := make(chan string)
	unlinkSub := service.unlinkEvent.Subscribe(unlinkCh)
	return &alibp2pTransport{pubkey: pubkey, sessionKey: sessionKey, service: service, unlinkSub: unlinkSub, unlinkCh: unlinkCh}
}

func newAlibp2pTransport(_ net.Conn) transport {
	return &alibp2pTransport{}
}

func (a alibp2pTransport) doEncHandshake(prv *ecdsa.PrivateKey, dialDest *discover.Node) (discover.NodeID, error) {
	log.Trace("alibp2pTransport.doEncHandshake", "peer", dialDest.ID.String())
	return dialDest.ID, nil
}

func (a alibp2pTransport) doProtoHandshake(our *protoHandshake) (*protoHandshake, error) {
	k, _ := alibp2p.ECDSAPubEncode(a.pubkey)
	//id, _ := discover.BytesID(append(a.pubkey.X.Bytes(), a.pubkey.Y.Bytes()...))
	id := discover.PubkeyID(a.pubkey)
	d := &protoHandshake{Version: baseProtocolVersion, Caps: our.Caps, Name: k, ID: id}
	log.Trace("alibp2pTransport.doProtoHandshake", "peer", id)
	return d, nil
}

func (a alibp2pTransport) ReadMsg() (Msg, error) {
	for !a.service.isStarted() {
		time.Sleep(1 * time.Second)
	}
	s := a.sessionKey
	if a.pubkey != nil {
		s, _ = alibp2p.ECDSAPubEncode(a.pubkey)
	}
	v, ok := a.service.msgReaders.Load(a.sessionKey)
	if !ok {
		return Msg{}, errors.New("alibp2p_reader_not_registed : " + s)
	}
	for {
		select {
		case msg, ok := <-v.(chan Msg):
			if !ok {
				log.Error("alibp2pTransport.read : EOF", "peer", s, "msg", msg, "ok", ok, "sessionKey", a.sessionKey)
				return Msg{}, io.EOF
			}
			log.Trace("alibp2pTransport-read-end", "msg", msg)
			return msg, nil
		case id := <-a.unlinkCh:
			if strings.Contains(a.sessionKey, id) {
				log.Trace("alibp2pTransport-read-unlink", "id", id)
				return Msg{}, errors.New(DELPEER_UNLINK)
			}
		}
	}
	return Msg{}, errors.New("readmsg error")
}

func (a alibp2pTransport) WriteMsg(msg Msg) error {
	now := time.Now()
	s, _ := alibp2p.ECDSAPubEncode(a.pubkey)
	data, err := msgToBytesFn(msg)
	if err != nil {
		log.Error("alibp2pTransport.write.error", "peer", s, "msg", msg, "err", err)
		return err
	}
	//log.Debug("alibp2pTransport.WriteMsg", "to", s, "msg", msg)
	a.service.msgWriter <- writeMsg{s, data, msg.Code}
	log.Trace("alibp2pTransport.WriteMsg.success", "peer", s, "msg", msg, "ttl", time.Since(now))
	return nil
}

func (a alibp2pTransport) close(err error) {
	defer a.unlinkSub.Unsubscribe()
	if r, ok := err.(DiscReason); ok {
		size, p, err := rlp.EncodeToReader(r)
		if err != nil {
			log.Error("rlp encode disReason", "err", err)
		} else {
			log.Trace("write disconnect msg", "reason", r)
			a.WriteMsg(Msg{Code: discMsg, Size: uint32(size), Payload: p})
		}
	}
	if err.Error() != DELPEER_UNLINK {
		closeErr := a.service.Close(a.pubkey)
		log.Trace("alibp2pTransport.close", "sessionkey", a.sessionKey, "err", err, "closeErr", closeErr)
		return
	}
	a.service.cleanConnect(a.pubkey, "alibp2pTransport-close", DELPEER_UNLINK)
	log.Trace("alibp2pTransport.close : unlink", "sessionkey", a.sessionKey, "err", err)
}

func (self *Alibp2p) isInbound(id string) bool {
	v, err := self.p2pservice.GetPeerMeta(id, string(INBOUND))
	if err != nil {
		return false
	}
	if inbound, ok := v.(bool); ok {
		return inbound
	}
	return false
}

func (self *Alibp2p) setRetry(sessionkey string, inbound bool) error {
	id, session, err := splitSessionkey(sessionkey)
	if err != nil {
		return err
	}
	//inbound := self.isInbound(id)
	self.retryList.Store(id, []interface{}{inbound, session})
	log.Debug("reset retry", "id", id, "inbound", inbound, "session", session)
	return nil
}

func NewAlibp2p(ctx context.Context, port, muxport, maxpeers int, networkid *big.Int, s *Server, packetFilter func(*ecdsa.PublicKey, uint16, uint32) error) *Alibp2p {
	var muxPort *big.Int = nil
	if muxport > 0 {
		muxPort = big.NewInt(int64(muxport))
	}
	srv := new(Alibp2p)
	srv.packetFilter = packetFilter
	srv.srv = s
	atomic.StoreInt32(&srv.started, 0)
	srv.msgReaders = new(sync.Map)
	srv.retryList = new(sync.Map)
	srv.allowPeers = new(sync.Map)
	srv.msgWriter = make(chan writeMsg)
	srv.maxpeers = maxpeers
	srv.peerCounter = newPeerCounter()
	srv.asyncRunner = alibp2p.NewAsyncRunner(ctx, 100, senderpool)
	srv.p2pservice = alibp2p.NewService(alibp2p.Config{
		Ctx:             ctx,
		Port:            uint64(port),
		MuxPort:         muxPort,
		Discover:        true,
		Networkid:       networkid,
		PrivKey:         s.PrivateKey,
		Bootnodes:       s.Alibp2pBootstrapNodes,
		BootstrapPeriod: bootstrapPeriod,
	})
	return srv
}

func (self *Alibp2p) isStarted() bool {
	if atomic.LoadInt32(&self.started) == 1 {
		return true
	}
	return false
}

func (self *Alibp2p) BootstrapOnce() error {
	return self.p2pservice.BootstrapOnce()
}

func (self *Alibp2p) Ping(id string) (string, error) {
	log.Info("<- alibp2p-ping <-", "id", id)
	resp, err := self.p2pservice.Request(id, pingpid, []byte("ping"))
	if err != nil {
		log.Error("<- alibp2p-ping-error <-", "id", id, "err", err)
		return "", err
	}
	log.Info("-> alibp2p-ping ->", "id", id, "pkg", string(resp), "err", err)
	return string(resp), err
}

func (self *Alibp2p) pingservice() {
	self.p2pservice.SetHandler(pingpid, func(session string, pubkey *ecdsa.PublicKey, rw io.ReadWriter) error {
		id, _ := alibp2p.ECDSAPubEncode(pubkey)
		buf := make([]byte, 4)
		t, err := rw.Read(buf)
		if err != nil {
			return err
		}
		log.Info("-> alibp2p-ping ->", "from", session, "id", id, "pkg", string(buf[:t]))
		if bytes.Equal(buf[:t], []byte("ping")) {
			log.Info("<- alibp2p-pong <-", "from", session, "id", id)
			rw.Write([]byte("pong"))
		} else {
			err = errors.New("error_msg")
			log.Info("<- alibp2p-err <-", "from", session, "id", id)
			rw.Write([]byte(err.Error()))
			return err
		}
		return nil
	})
}

func (self *Alibp2p) mailboxservice() {
	self.msgReaders.Store(mailboxpid, make(chan Msg))
	self.p2pservice.SetHandler(mailboxpid, func(session string, pubkey *ecdsa.PublicKey, rw io.ReadWriter) error {
		var (
			id, _ = alibp2p.ECDSAPubEncode(pubkey)
			buf   = alibp2p.GetBuf(6)
		)
		defer alibp2p.PutBuf(buf)
		t, err := rw.Read(buf)
		if t < 6 || err != nil {
			log.Error("mailboxservice read format error", "head-byte-len", t, "err", err)
			return errors.New("error packet")
		}

		msgType, size, err := packetHeadDecode(buf)
		if err != nil {
			log.Error("mailboxservice msg head decode error", "err", err)
			return errors.New("error packet")
		}
		if self.packetFilter != nil {
			if err := self.packetFilter(pubkey, msgType, size); err != nil {
				log.Error("mailboxservice packetFilter error", "err", err)
				return err
			}
		}
		log.Trace("mailboxservice head", "id", id, "msgType", msgType, "size", size, "session", session)
		data := alibp2p.GetBuf(int(size))
		defer alibp2p.PutBuf(data)

		if _, err := io.ReadFull(rw, data); err != nil {
			if err != nil {
				log.Error("mailboxservice msg read error", "err", err, "from", id, "msgType", msgType, "size", size, "session", session)
				return err
			}
		}

		msg, err := bytesToMsgFn(data)
		if err != nil {
			log.Error("mailboxservice bytesToMsgFn error", "err", err)
			return errors.New("error packet")
		}

		v, ok := self.msgReaders.Load(mailboxpid)
		if ok {
			errCh := make(chan error)
			go func(errCh chan error) {
				defer func() {
					if err := recover(); err != nil {
						log.Error("mailboxservice may be disconnected", "err", err)
						errCh <- io.EOF
					} else {
						errCh <- nil
					}
				}()
				v.(chan Msg) <- msg
			}(errCh)
			err := <-errCh
			log.Trace("mailboxservice read over", "err", err, "msg", msg)
			return err
		}
		log.Error("mailboxservice error", "err", "handler not started")
		return nil
	})
}

func (self *Alibp2p) msgservice() {

	self.p2pservice.SetHandler(msgpid, func(session string, pubkey *ecdsa.PublicKey, rw io.ReadWriter) error {
		var (
			id, _ = alibp2p.ECDSAPubEncode(pubkey)
			key   = genSessionkey(id, session)
			//counter = 0
			buf = alibp2p.GetBuf(6)
			now = time.Now()
		)
		defer alibp2p.PutBuf(buf)
		t, err := rw.Read(buf)
		if t < 6 || err != nil {
			log.Error("alibp2p msg format error ( need byte-len == 6 )", "head-byte-len", t, "err", err)
			return errors.New("error packet")
		}
		msgType, size, _ := packetHeadDecode(buf)
		if self.packetFilter != nil {
			if err := self.packetFilter(pubkey, msgType, size); err != nil {
				return err
			}
		}
		data := alibp2p.GetBuf(int(size))
		defer alibp2p.PutBuf(data)
		if n, err := io.ReadFull(rw, data); err != nil {
			log.Error("alibp2p msg read err", "err", err, "from", id, "msgType", msgType, "size", size, "n", n, "session", session)
			return err
		}
		log.Trace("msgservice-read", "msgType", msgType, "size", size)
		msg, err := bytesToMsgFn(data)
		if err != nil {
			log.Error("alibp2p msg decode read error", "err", err)
			return err
		}
		// retry for delay
		v, ok := self.msgReaders.Load(key)
		if !ok && msgType == 16 {
			for i := 0; i < 3; i++ {
				time.Sleep(1 * time.Second)
				v, ok = self.msgReaders.Load(key)
			}
		}
		log.Trace("msg-dispatch", "from", id, "msg", msg, "found-recv", ok)
		if ok {
			errCh := make(chan error)
			go func(errCh chan error) {
				defer func() {
					if err := recover(); err != nil {
						log.Error("may be disconnected", "err", err)
						errCh <- io.EOF
					} else {
						errCh <- nil
					}
				}()
				v.(chan Msg) <- msg
			}(errCh)
			err := <-errCh
			log.Trace("msg-handle", "from", id, "msg", msg, "err", err, "ttl", time.Since(now))
			return err
		}
		e := fmt.Sprintf("msg lost : recver not found : %s", id)
		resp, err := self.p2pservice.Request(id, premsgpid, unlink.Bytes())
		self.cleanConnect(pubkey, session, DELPEER_UNLINK)
		log.Warn("msg-dispatch-skip", "reason", e, "id", id, "err", err, "unlink-resp", resp)
		return errors.New(e)
	})
}

func (self *Alibp2p) Start() {
	defer atomic.StoreInt32(&self.started, 1)
	go self.loopMsg()
	go self.loopMailbox()
	go self.loopRetrySetup()
	self.pingservice()
	self.preservice()
	self.msgservice()
	self.mailboxservice()
	self.p2pservice.OnConnected(alibp2p.CONNT_TYPE_DIRECT, self.outboundPreMsg, self.onConnected)
	self.p2pservice.OnDisconnected(self.onDisconnected)
	self.p2pservice.Start()
	log.Trace("Alibp2p-started")

}

func (self *Alibp2p) outboundPreMsg() (protocolID string, pkg []byte) {
	protocolID = premsgpid
	total := self.peerCounter.total(OUTBOUND)
	if total >= self.srv.Config.MaxPeers/3 {
		pkg = ignore.Bytes()
	} else {
		pkg = setup.Bytes()
	}
	log.Trace("outboundPreMsg",
		"req", pkg,
		"total", self.peerCounter.total(EMPTY),
		"total-in", self.peerCounter.total(INBOUND),
		"total-out", self.peerCounter.total(OUTBOUND),
		"maxpeers", self.srv.Config.MaxPeers)
	return
}

func (self *Alibp2p) preMsg() (protocolID string, pkg []byte) {
	protocolID = premsgpid
	total := self.peerCounter.total(EMPTY)
	if total >= self.srv.Config.MaxPeers {
		pkg = ignore.Bytes()
	} else {
		pkg = setup.Bytes()
	}
	log.Trace("preMsg", "pkg", pkg, "current", total, "maxpeers", self.srv.Config.MaxPeers)
	return
}

func (self *Alibp2p) preservice() {
	self.p2pservice.SetHandler(premsgpid, func(session string, pubkey *ecdsa.PublicKey, rw io.ReadWriter) error {
		id, _ := alibp2p.ECDSAPubEncode(pubkey)
		in := self.isInbound(id)
		sessionKey := genSessionkey(id, session)
		buf := make([]byte, 1)
		_, err := rw.Read(buf)
		if err != nil {
			return err
		}

		if bytes.Equal(buf, unlink.Bytes()) {
			_, err := rw.Write(buf)
			log.Trace("preservice-recv-unlink", "action", buf, "id", id, "inbound", in, "resp-err", err, "session", session)
			self.cleanConnect(pubkey, session, DELPEER_UNLINK)
			self.peerCounter.del(id, session, true)
			return nil
		}

		_, pkg := self.preMsg()
		if allow, ok := self.allowPeers.Load(sessionKey);
			ok && allow.(bool) && connBehaviour(pkg[0]) == ignore {
			pkg = setup.Bytes()
		}
		log.Trace("preservice-answer", "id", id, "inbound", in, "recv", buf, "answer", pkg, "session", session)
		rw.Write(pkg)

		if bytes.Equal(buf, relink.Bytes()) {
			log.Trace("preservice-recv-resetup", "resp", pkg, "action", buf, "id", id, "inbound", in, "session", session)
			self.onConnected(in, session, pubkey, pkg)
		}

		return nil
	})
}

func (self *Alibp2p) loopMailbox() {
	log.Info("Alibp2p-loopMailbox-start")
	var (
		msgCh  = make(chan []interface{})
		msgSub = alibp2pMailboxEvent.Subscribe(msgCh)
		sendFn = func(ctx context.Context, args []interface{}) {
			data := args[0].([]interface{})
			to, mt, rd := data[0].(*ecdsa.PublicKey), data[1].(uint64), data[2].([]byte)
			s, _ := alibp2p.ECDSAPubEncode(to)
			//log.Trace("loopMailbox-write-start", "datalen", len(rd), "tn", ctx.Value("tn"))
			pk := make([]byte, 0)
			header := packetHeadEncode(uint16(mt), rd)
			pk = append(pk, header...)
			pk = append(pk, rd...)

			err := self.p2pservice.SendMsgAfterClose(s, mailboxpid, pk)
			if err != nil {
				log.Error("Alibp2p.msgservice.loopMailbox.error", "err", err, "to", s, "header", header)
			}
			log.Trace("loopMailbox-write-end", "err", err, "datalen", len(rd))
		}
	)

	defer func() {
		msgSub.Unsubscribe()
		log.Warn("alibp2pMailboxEvent-Unsubscribe")
	}()

	for {
		select {
		case data := <-msgCh:
			self.asyncRunner.Apply(sendFn, data)
		case <-self.stop:
			return
		}
	}

	log.Info("Alibp2p-loopMailbox-end")
}

func (self *Alibp2p) loopMsg() {
	log.Info("Alibp2p-loopMsg-start")
	var sendFn = func(ctx context.Context, args []interface{}) {
		var (
			//now    = time.Now()
			//tsize  = self.asyncRunner.Size()
			packet = args[0].(writeMsg)
			pk     = make([]byte, 0)
		)
		log.Trace("Alibp2p.msgservice.send", "to", packet.to, "msgType", packet.msgType, "size", len(packet.data), "head", packet.data[:6], "tn", ctx.Value("tn"))
		header := packetHeadEncode(uint16(packet.msgType), packet.data)
		pk = append(pk, header...)
		pk = append(pk, packet.data...)
		err := self.p2pservice.SendMsgAfterClose(packet.to, msgpid, pk)
		if err != nil {
			log.Error("Alibp2p.msgservice.send.error", "tn", ctx.Value("tn"), "err", err, "to", packet.to, "header", header)
		}
	}
	for {
		select {
		case packet := <-self.msgWriter:
			self.asyncRunner.Apply(sendFn, packet)
		case <-self.stop:
			return
		}
	}
	log.Info("Alibp2p-loopMsg-end")
}

func (self *Alibp2p) Stop() {
	defer atomic.StoreInt32(&self.started, 0)
	close(self.stop)
}

func NewAlibp2pMailboxReader(srv *Server) *Peer {
	var c = &conn{
		transport: newAlibp2pTransport2(nil, mailboxpid, srv.alibp2pService), cont: make(chan error),
		alibp2pservice: srv.alibp2pService,
	}
	return &Peer{rw: c}
}

func (self *Alibp2p) loopRetrySetup() {
	var (
		timer       = time.NewTimer(setupRetryPeriod * time.Second)
		syncmapSize = func(m *sync.Map) int {
			t := 0
			m.Range(func(key, value interface{}) bool {
				t += 1
				return true
			})
			return t
		}
		contains = func(arr []string, s string) bool {
			for _, a := range arr {
				if strings.Contains(a, s) {
					return true
				}
			}
			return false
		}
		retry = func(fn func()) {
			var (
				directs, _ = self.p2pservice.Conns()
				totalPeer  = self.peerCounter.total(EMPTY)
			)
			log.Debug("loopRetrySetup >>",
				"directs", len(directs),
				"total", totalPeer,
				"total-in", self.peerCounter.total(INBOUND),
				"total-out", self.peerCounter.total(OUTBOUND),
				"maxpeers", self.maxpeers,
				"turnoff", self.maxpeers/3)

			if totalPeer < self.maxpeers/3 && len(directs) > totalPeer {
				if syncmapSize(self.retryList) == 0 {
					// reset retryList
					totalRetry := self.maxpeers * 2 / 3
					for _, saddr := range directs {
						id := strings.Split(saddr, "/ipfs/")[1]
						if totalRetry == 0 {
							break
						}
						session, inbound, err := self.p2pservice.GetSession(id)
						if err != nil {
							log.Error("getsession fail", "id", id, "err", err)
							continue
						}
						if !self.peerCounter.has(id) {
							self.setRetry(genSessionkey(id, session), inbound)
							totalRetry -= 1
						}
					}
					log.Debug("reset-retryList", "directs", len(directs), "retryList", syncmapSize(self.retryList))
				}
				fn()
			}
		}
		do = func() {
			target := self.maxpeers / 3
			self.retryList.Range(func(k, v interface{}) bool {
				id, args := k.(string), v.([]interface{})
				inbound, session := args[0].(bool), args[1].(string)
				proto, pkg := self.preMsg()
				directs, _ := self.p2pservice.Conns()
				if contains(directs, id) {
					resp, err := self.p2pservice.Request(id, proto, relink.Bytes())
					if err != nil {
						log.Error("setupRetryLoop-do-1", "err", err, "id", id)
						self.retryList.Delete(k)
					}
					pubkey, err := alibp2p.ECDSAPubDecode(id)
					if err != nil {
						log.Error("setupRetryLoop-do-2", "err", err, "id", id)
						self.retryList.Delete(k)
					}
					log.Debug("setupRetryLoop-do", "id", id, "inbound", inbound, "req", pkg, "resp", resp, "session", session)
					self.onConnected(inbound, session, pubkey, resp)
					if bytes.Equal(resp, setup.Bytes()) {
						target -= 1
						if target == 0 {
							return false
						}
					}
				} else {
					log.Debug("setupRetryLoop-del : not a direct conn", "id", id)
					self.retryList.Delete(k)
				}
				return true
			})
		}
	)
	for {
		select {
		case <-timer.C:
			retry(do)
		case <-self.stop:
			return
		}
		timer.Reset(setupRetryPeriod * time.Second)
	}
}

func (self *Alibp2p) checkConn(id, session string, preRtn []byte, inbound bool) (err error) {
	defer func() {
		if err != nil {
			self.setRetry(genSessionkey(id, session), inbound)
		}
	}()
	if self.peerCounter.cmp(self.maxpeers, EMPTY) >= 0 {
		err = errors.New("too many peers")
		return
	}
	if !inbound && self.peerCounter.cmp(self.maxpeers/3, OUTBOUND) >= 0 {
		err = errors.New("too many outbounds")
		return
	}
	// inbound == false 时，必须要带上 preRtn 消息，否则就是错误包
	if !inbound && (len(preRtn) == 0 || len(preRtn) > 1) {
		err = fmt.Errorf("error pre msg : %v", preRtn)
		return
	}

	if preRtn != nil && len(preRtn) > 0 && connBehaviour(preRtn[0]) == ignore {
		// 对方 peers 满了，定期重试
		err = errors.New("remote too many peers")
		return
	}
	return
}

func (self *Alibp2p) onConnected(inbound bool, session string, pubkey *ecdsa.PublicKey, preRtn []byte) {

	var (
		err   error
		id, _ = alibp2p.ECDSAPubEncode(pubkey)
		key   = genSessionkey(id, session)
		c     = &conn{
			session:   session,
			fd:        nil,
			transport: newAlibp2pTransport2(pubkey, key, self), cont: make(chan error),
			alibp2pservice: self,
		}
		//distID, _  = discover.BytesID(append(pubkey.X.Bytes(), pubkey.Y.Bytes()...))
		distID     = discover.PubkeyID(pubkey)
		distNode   = discover.NewNode(distID, net.IPv4(1, 1, 1, 1), 0, 0)
		errcleanFn = func(id, key string, err error) {
			log.Warn("alibp2p err clean msgReaders", "err", err, "id", id, "sessionKey", key)
			self.msgReaders.Delete(key)
			self.retryList.Delete(id)
		}
		bound connType
	)

	self.peerCounter.add(id, session)
	self.msgReaders.Store(key, make(chan Msg, msgCache))
	self.retryList.Delete(id)
	self.p2pservice.PutPeerMeta(id, string(INBOUND), inbound)

	if inbound {
		c.flags, bound = inboundConn, INBOUND
	} else {
		c.flags, bound = dynDialedConn, OUTBOUND
	}

	log.Debug("[->peer] onConnected event",
		"inbound", inbound,
		"preRtn", preRtn,
		"total", self.peerCounter.total(EMPTY),
		"total-in", self.peerCounter.total(INBOUND),
		"total-out", self.peerCounter.total(OUTBOUND),
		"id", id,
		"session", session)

	if err = self.srv.setupConn(c, c.flags, distNode); err != nil {
		errcleanFn(id, key, err)
		c.close(err)
		log.Error("Setting up connection failed", "id", c.id, "err", err)
		return
	}

	if reason := self.checkConn(id, session, preRtn, inbound); reason != nil {
		go func() {
			log.Trace("unlink-task-gen : exec after 5 sec", "id", id, "inbound", inbound, "reason", reason)
			// 这个地方要给 setupConn 流出足够多的时间
			time.Sleep(5 * time.Second)
			resp, err := self.p2pservice.Request(id, premsgpid, unlink.Bytes())
			self.cleanConnect(pubkey, session, DELPEER_UNLINK)
			log.Trace("unlink-task-done", "id", id, "inbound", inbound, "resp", resp, "err", err)
		}()
	}

	self.allowPeers.Store(key, inbound)
	self.peerCounter.set(id, session, string(bound))

	log.Trace("peerscounter : add",
		"maxpeers", self.maxpeers,
		"total", self.peerCounter.total(EMPTY),
		"total-in", self.peerCounter.total(INBOUND),
		"total-out", self.peerCounter.total(OUTBOUND),
		"id", id, "session", session)
}

func (self *Alibp2p) onDisconnected(session string, pubkey *ecdsa.PublicKey) {
	id, _ := alibp2p.ECDSAPubEncode(pubkey)
	log.Debug("[<-peer] onDisconnected event", "id", id, "inbound", self.isInbound(id), "session", session)
	self.cleanConnect(pubkey, session, DELPEER_DISCONN)
}

func (self *Alibp2p) cleanConnect(pubkey *ecdsa.PublicKey, session, delpeerAction string) {
	id, _ := alibp2p.ECDSAPubEncode(pubkey)
	key := genSessionkey(id, session)
	log.Trace("cleanConnect", "id", id, "inbound", self.isInbound(id), "delpeer", delpeerAction)
	defer func() {
		//self.allowPeers.Delete(key)
		if errMsg := recover(); errMsg != nil {
			log.Warn("onDisconnected defer", "err", errMsg)
		}
		switch delpeerAction {
		case DELPEER_UNLINK:
			self.peerCounter.del(id, session, true)
		case DELPEER_DISCONN:
			self.peerCounter.del(id, session, false)
		}
		log.Trace("peerscounter : del",
			"max", self.maxpeers,
			"total", self.peerCounter.total(EMPTY),
			"total-in", self.peerCounter.total(INBOUND),
			"total-out", self.peerCounter.total(OUTBOUND),
			"id", id, "session", session, )
	}()
	v, ok := self.msgReaders.Load(key)
	if ok && v != nil {
		log.Trace("cleanConnect-unlinkEvent-send", "id", id)
		n := self.unlinkEvent.Send(id)
		log.Trace("cleanConnect-unlinkEvent-done", "nsent", n)
		msgCh := v.(chan Msg)
		close(msgCh)
		self.msgReaders.Delete(key)
	}
	self.srv.delpeer <- peerDrop{
		&Peer{rw: &conn{id: discover.PubkeyID(pubkey), session: session}},
		errors.New(delpeerAction),
		false}
}

func (self *Alibp2p) Myid() (id string, addrs []string) {
	id, addrs = self.p2pservice.Myid()
	return
}

func (self *Alibp2p) Close(pubkey *ecdsa.PublicKey) error {
	peerid, _ := alibp2p.ECDSAPubEncode(pubkey)
	err := self.p2pservice.ClosePeer(pubkey)
	log.Info("Alibp2p.Close peer", "id", peerid, "err", err)
	return err
}

func (self *Alibp2p) Findpeer(pubkey *ecdsa.PublicKey) (string, []string, error) {
	if pubkey == nil {
		return "", nil, errors.New("nil point of input pubkey")
	}
	if self.srv.PrivateKey.PublicKey == *pubkey {
		id, addr := self.Myid()
		return id, addr, nil
	}
	id, err := alibp2p.ECDSAPubEncode(pubkey)
	if err != nil {
		return "", nil, err
	}
	addrs, err := self.p2pservice.Findpeer(id)
	if err != nil {
		return "", nil, err
	}
	return id, addrs, nil
}

func (self *Alibp2p) Table() map[string][]string {
	return self.p2pservice.Table()
}

func (self *Alibp2p) PreConnect(pubkey *ecdsa.PublicKey) error {
	return self.p2pservice.PreConnect(pubkey)
}

func (self *Alibp2p) Connect(url string) error {
	return self.p2pservice.Connect(url)
}

func packetHeadEncode(msgType uint16, data []byte) []byte {
	var psize = uint32(len(data))
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, &msgType)
	binary.Write(buf, binary.BigEndian, &psize)
	return buf.Bytes()
}

func packetHeadDecode(header []byte) (msgType uint16, size uint32, err error) {
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

func genSessionkey(id, session string) string {
	return fmt.Sprintf("%s%s", id, session)
}

func splitSessionkey(sessionkey string) (id, session string, err error) {
	arr := strings.Split(sessionkey, "session:")
	if len(arr) != 2 {
		return "", "", errors.New("error sessionkey format")
	}
	return arr[0], fmt.Sprintf("session:%s", arr[1]), nil
}
