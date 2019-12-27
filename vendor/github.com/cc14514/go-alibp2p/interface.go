/*************************************************************************
 * Copyright (C) 2016-2019 PDX Technologies, Inc. All Rights Reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * @Time   : 2019/11/6 2:05 下午
 * @Author : liangc
 *************************************************************************/

package alibp2p

import (
	"crypto/ecdsa"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	"io"
	"time"
)

type (
	StreamHandler   func(sessionId string, pubkey *ecdsa.PublicKey, rw io.ReadWriter) error
	PreMsg          func() (string, []byte)
	ConnectEvent    func(inbound bool, sessionId string, pubKey *ecdsa.PublicKey, preRtn []byte)
	DisconnectEvent func(sessionId string, pubKey *ecdsa.PublicKey)

	Libp2pService interface {
		Alibp2pService
		SetStreamHandler(protoid string, handler func(s network.Stream))
		SendMsg(to, protocolID string, msg []byte) (peer.ID, network.Stream, int, error)
		Nodekey() *ecdsa.PrivateKey
	}

	Alibp2pService interface {
		Start()
		Myid() (id string, addrs []string)
		Connect(url string) error
		ClosePeer(pubkey *ecdsa.PublicKey) error
		SetBootnode(peer ...string) error
		SetHandler(pid string, handler StreamHandler)

		SendMsgAfterClose(to, protocolID string, msg []byte) error
		Request(to, proto string, msg []byte) ([]byte, error)

		RequestWithTimeout(to, proto string, pkg []byte, timeout time.Duration) ([]byte, error)

		PreConnect(pubkey *ecdsa.PublicKey) error

		OnConnected(ConnType, PreMsg, ConnectEvent)
		OnDisconnected(DisconnectEvent)

		Table() map[string][]string // map => {id:addrs}
		Conns() (direct []string, relay []string)
		Peers() (direct []string, relay map[string][]string, total int)

		PutPeerMeta(id, key string, v interface{}) error
		GetPeerMeta(id, key string) (interface{}, error)

		GetSession(id string) (session string, inbound bool, err error)

		Findpeer(id string) ([]string, error) // return addrs,err

		BootstrapOnce() error

		Put(k string, v []byte) error
		Get(k string) ([]byte, error)
	}
)
