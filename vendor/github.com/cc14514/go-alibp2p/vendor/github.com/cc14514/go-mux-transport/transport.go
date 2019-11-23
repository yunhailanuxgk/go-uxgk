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
 * @Time   : 2019/10/21 5:15 下午
 * @Author : liangc
 *************************************************************************/

package netmux

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/transport"
	"github.com/libp2p/go-tcp-transport"
	ma "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr-net"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const P_MUX = 390

var MuxProtocol = ma.Protocol{
	Name:       "mux",
	Code:       P_MUX,
	VCode:      ma.CodeToVarint(P_MUX),
	Size:       32,
	Path:       false,
	Transcoder: new(MuxTranscoder),
}

func init() { ma.AddProtocol(MuxProtocol) }

type (
	MuxTranscoder struct{}
	MuxListener   struct {
		//tl transport.Listener
		maddr ma.Multiaddr
		manet.Listener
	}
	MuxTransport struct {
		tpt *tcp.TcpTransport
	}
)

func (m *MuxListener) Close() error {
	return nil
}

func (m *MuxListener) Multiaddr() ma.Multiaddr {
	return m.maddr
}

func (m *MuxListener) Accept() (manet.Conn, error) {
	log.Println("netmux-transport-started", m.maddr.String())
	select {}
	return nil, errors.New("[ignoe error] : netmux can not do accept")
}

func NewMuxTransport(tpt *tcp.TcpTransport) *MuxTransport {
	mt := new(MuxTransport)
	mt.tpt = tpt
	return mt
}

func (m MuxTranscoder) StringToBytes(s string) ([]byte, error) {
	ports := strings.Split(s, ":")
	p1, p2 := ports[0], ports[1]
	b1, err := ma.TranscoderPort.StringToBytes(p1)
	if err != nil {
		return nil, err
	}
	b2, err := ma.TranscoderPort.StringToBytes(p2)
	if err != nil {
		return nil, err
	}
	r := append(b1, b2...)
	return r, nil
}

func (m MuxTranscoder) BytesToString(b []byte) (string, error) {
	s1, err := ma.TranscoderPort.BytesToString(b[:2])
	if err != nil {
		return "", err
	}
	s2, err := ma.TranscoderPort.BytesToString(b[2:])
	if err != nil {
		return "", err
	}
	r := fmt.Sprintf("%s:%s", s1, s2)
	return r, nil
}

func (m MuxTranscoder) ValidateBytes(b []byte) error {
	if len(b) != 4 {
		return errors.New("mux protocol format error")
	}
	return nil
}

func parseMuxargs(raddr ma.Multiaddr) (ip string, fp, tp int, err error) {
	_, ip, err = manet.DialArgs(raddr)
	if err != nil {
		return
	}
	var (
		fport, tport string
		muxAddr      ma.Multiaddr
		addrs        = ma.Split(raddr)
	)
	for _, maddr := range addrs {
		if maddr.Protocols()[0].Code == MuxProtocol.Code {
			muxAddr = maddr
			break
		}
	}
	fport, err = ma.TranscoderPort.BytesToString(muxAddr.Bytes()[2:4])
	if err != nil {
		return
	}
	tport, err = ma.TranscoderPort.BytesToString(muxAddr.Bytes()[4:6])
	if err != nil {
		return
	}

	fp, err = strconv.Atoi(fport)
	if err != nil {
		return
	}
	tp, err = strconv.Atoi(tport)
	if err != nil {
		return
	}
	return
}

func readHttpPacket(conn io.Reader) (txt []byte, err error) {
	var (
		rtn    bool
		buff   = make([]byte, 1)
		fs, fe = make([]int, 2), make([]int, 2)
	)
	for {
		_, err = conn.Read(buff)
		if err != nil {
			return
		}
		pos := len(txt)
		switch buff[0] {
		case '\r':
			fs[0], fs[1] = pos, '\r'
		case '\n':
			if pos > 0 && pos-2 == fe[0] && pos-1 == fs[0] {
				//end
				rtn = true
			}
			fe[0], fe[1] = pos, '\n'
		}
		txt = append(txt, buff[0])
		if rtn {
			return
		}
	}

	return nil, nil
}

func dialMux(ip string, fport, tport int) (conn net.Conn, err error) {
	var (
		txt    []byte
		dialer = &net.Dialer{Timeout: 15 * time.Second}
		addr   = &net.TCPAddr{IP: net.ParseIP(ip), Port: fport}
		req1   = fmt.Sprintf("CONNECT conn://localhost:%d HTTP/1.1\r\nHost: localhost:%d\r\n\r\n", tport, tport)
	)
	conn, err = dialer.Dial("tcp", addr.String())
	if err != nil {
		log.Println("dialMux-error-1", "err", err, "ip", ip, "fport", fport)
		return
	}
	_, err = conn.Write([]byte(req1))
	if err != nil {
		return
	}
	txt, err = readHttpPacket(conn)
	if err != nil {
		log.Println("dialMux-error-2", "err", err)
		return
	}
	if !bytes.Contains(txt[:], []byte("HTTP/1.1 200")) {
		log.Println("dialMux-error-3", "err", err, "ip", ip, "fport", fport)
		return
	}
	return
}

func (m MuxTransport) Dial(ctx context.Context, raddr ma.Multiaddr, p peer.ID) (transport.CapableConn, error) {
	ip, fport, tport, err := parseMuxargs(raddr)
	if err != nil {
		return nil, err
	}
	log.Println("dialMux", "ip", ip, "fport", fport, "tport", tport)
	c, err := dialMux(ip, fport, tport)
	if err != nil {
		return nil, err
	}
	conn, err := manet.WrapNetConn(c)
	if err != nil {
		return nil, err
	}
	return m.tpt.Upgrader.UpgradeOutbound(ctx, m.tpt, conn, p)
}

func (m MuxTransport) CanDial(addr ma.Multiaddr) bool {
	_, err := addr.ValueForProtocol(P_MUX)
	return err == nil
}

func (m MuxTransport) Listen(laddr ma.Multiaddr) (transport.Listener, error) {
	ml := &MuxListener{maddr: laddr}
	return m.tpt.Upgrader.UpgradeListener(m, ml), nil
}

func (m MuxTransport) Protocols() []int {
	return []int{MuxProtocol.Code}
}

func (m MuxTransport) Proxy() bool {
	return false
}

func MuxAddress(maddrs []ma.Multiaddr) (muxaddr ma.Multiaddr, ok bool) {
	for _, maddr := range maddrs {
		if maddr == nil {
			continue
		}
		ok, _, _, _ = SplitMuxAddr(maddr)
		if ok {
			muxaddr = maddr
			return
		}
	}
	return
}

func SplitMuxAddr(maddr ma.Multiaddr) (ok bool, ip string, fport, tport int) {
	if maddr == nil {
		return
	}
	var muxAddr ma.Multiaddr
	addrs := ma.Split(maddr)
	for _, maddr := range addrs {
		if maddr.Protocols()[0].Code == MuxProtocol.Code {
			ok = true
			muxAddr = maddr
			break
		}
	}
	if ok {
		s1, _ := ma.TranscoderPort.BytesToString(muxAddr.Bytes()[2:4])
		s2, _ := ma.TranscoderPort.BytesToString(muxAddr.Bytes()[4:6])
		fport, _ = strconv.Atoi(s1)
		tport, _ = strconv.Atoi(s2)
		_, ip, _ = manet.DialArgs(maddr)
	}
	return
}

func MaddrsToPorts(maddrs []ma.Multiaddr) map[string]string {
	portmap := make(map[string]string)
	for _, maddr := range maddrs {
		if maddr == nil {
			continue
		}
		if ok, _, fport, tport := SplitMuxAddr(maddr); ok {
			portmap[fmt.Sprintf("%d:%d", fport, tport)] = MuxProtocol.Name
		} else {
			p, h, err := manet.DialArgs(maddr)
			if err == nil && strings.Contains(h, ":") {
				net := p
				switch p {
				case "tcp4", "tcp6":
					net = "tcp"
				case "udp4", "udp6":
					net = "udp"
				}
				portmap[strings.Split(h, ":")[1]] = net
			}
		}
	}
	return portmap
}
func MaddrsToIps(maddrs []ma.Multiaddr) map[string]string {
	ipmap := make(map[string]string)
	for _, maddr := range maddrs {
		if maddr != nil {
			x, y, e := manet.DialArgs(maddr)
			if e == nil {
				ipmap[strings.Split(y, ":")[0]] = x
			}
		}
	}
	return ipmap
}

type muxfn string

const (
	realip muxfn = "realip"
	ping         = "ping"
)

var muxUrl = func(muxport int, fn muxfn) string {
	return fmt.Sprintf("http://127.0.0.1:%d/chainmux/%s", muxport, fn)
}

func GetRealIP(r, l ma.Multiaddr, muxport int) (string, error) {
	_, a, err := manet.DialArgs(r)
	if err != nil {
		return "", err
	}
	_, b, err := manet.DialArgs(l)
	if err != nil {
		return "", err
	}
	session := fmt.Sprintf("%s%s", strings.Split(a, ":")[1], strings.Split(b, ":")[1])
	log.Println("get-realip-from-netmux", "mux", r, "local", l, "session", session)
	url := muxUrl(muxport, realip)
	client := &http.Client{}
	request, _ := http.NewRequest("GET", url, nil)
	request.Header.Add("sessionid", session)
	response, err := client.Do(request)
	log.Println("- get realip -> err", err, "sessionid", request.Header.Get("sessionid"))
	if err != nil {
		return "", err
	} else {
		defer response.Body.Close()
		data, err := ioutil.ReadAll(response.Body)
		if response.StatusCode == 200 {
			log.Println("<- get realip -", "err", err, "stateCode", response.StatusCode, "body", string(data))
			return string(data), nil
		}
		return "", fmt.Errorf("get realip fail : statecode %d", response.StatusCode)
	}
}

func Register(ctx context.Context, muxport, port int) {
	var (
		wait       = 10
		url        = muxUrl(muxport, ping)
		client     = &http.Client{}
		request, _ = http.NewRequest("GET", url, nil)
	)
	request.Header.Add("k", fmt.Sprintf("conn://localhost:%d", port))
	request.Header.Add("v", fmt.Sprintf("localhost:%d", port))
	go func() {
		for {
			response, err := client.Do(request)
			if err != nil && wait < 120 {
				wait += 1
			} else if err == nil {
				wait = 10
				response.Body.Close()
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Duration(wait) * time.Second):
			}
		}
	}()
}
