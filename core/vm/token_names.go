package vm

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/yunhailanuxgk/go-uxgk/common"
	"github.com/yunhailanuxgk/go-uxgk/crypto"
	"github.com/yunhailanuxgk/go-uxgk/log"
	"math/big"
	"strings"
)

/*存储定义：

reg :
	key = hash("owner",name,symbol) , val = ownerAddr
	key = hash("state",name,symbol) , val = hash("reg")

bind :
	key = name+symbol , val = erc20Addr
	key = hash("state",name,symbol) , val = hash("bind")

whois : query

unbind :
	TODO
exchange :
	TODO
*/
var (
	TokennamesAddr = common.HexToAddress("0x222")

	regKeyFn = func(name, symbol []byte) common.Hash {
		return common.BytesToHash(crypto.Keccak256([]byte("owner"), name, symbol))
	}
	stateKeyFn = func(name, symbol []byte) common.Hash {
		return common.BytesToHash(crypto.Keccak256([]byte("state"), name, symbol))
	}
	bindKeyFn = func(name, symbol []byte) common.Hash {
		return common.BytesToHash(append(name, symbol...))
	}

	nsFillFn = func(name, symbol []byte) ([]byte, []byte) {
		n := make([]byte, 20)
		copy(n, name)
		s := make([]byte, 12)
		copy(s, symbol)
		return n, s
	}
	nsFixFn = func(name, symbol []byte) ([]byte, []byte) {
		fix := func(b []byte) []byte {
			z := []byte{0}
			n := bytes.LastIndex(name, z)
			return b[n+1:]
		}
		return fix(name), fix(symbol)
	}
	nsHash = func(name, symbol string) common.Hash {
		name, symbol = strings.ToLower(name), strings.ToLower(symbol)
		a, b := nsFillFn([]byte(name), []byte(symbol))
		return common.BytesToHash(crypto.Keccak256(a, b))
	}
)

type Tokennames struct {
	nameprice *big.Int
	func_reg,
	func_bind,
	func_exchange,
	func_whois string
	emptyHash common.Hash
	static    *staticNameMap
	get       func(db StateDB, k common.Hash) common.Hash
	set       func(db StateDB, k, v common.Hash)
}

func (l *Tokennames) RequiredGas(input []byte) uint64 {
	if l.func_whois == "" {
		l.static = initStaticNameMap()
		l.nameprice, _ = new(big.Int).SetString("99000000000000000000", 10) // 99uxgk
		l.emptyHash = common.Hash{}
		l.func_reg = "reg"
		l.func_bind = "bind"
		l.func_exchange = "exchange"
		l.func_whois = "whois"
		l.get = func(db StateDB, k common.Hash) common.Hash {
			v := db.GetState(TokennamesAddr, k)
			return v
		}
		l.set = func(db StateDB, k, v common.Hash) {
			db.SetState(TokennamesAddr, k, v)
		}

	}
	return 21000
}

// 价格 99 uxgk
func (l *Tokennames) reg(ctx *PrecompiledContext, name, symbol []byte) ([]byte, error) {
	log.Info("Tokennames.reg", "owner", ctx.contract.Caller().Hex(), "name", string(name), "symbol", string(symbol), "value", ctx.contract.value)

	if s := l.static.has(name, symbol); s != nil {
		return nil, fmt.Errorf("(%s, %s) was registed", name, symbol)
	}

	if ctx.contract.value == nil || ctx.contract.value.Cmp(l.nameprice) < 0 {
		log.Info("Tokennames.reg-error-1", "owner", ctx.contract.Caller().Hex(), "name", string(name), "symbol", string(symbol), "value", ctx.contract.value)
		return nil, errors.New("less than nameprice (99uxgk)")
	}
	/*
		reg :
			key = hash("owner",name,symbol) , val = ownerAddr
			key = hash("state",name,symbol) , val = hash("reg")
	*/
	db := ctx.evm.StateDB
	name, symbol = nsFillFn(name, symbol)
	owner := l.get(db, regKeyFn(name, symbol))
	if owner != l.emptyHash {
		log.Info("Tokennames.reg-error-2", "owner", ctx.contract.Caller().Hex(), "name", string(name), "symbol", string(symbol), "value", ctx.contract.value)
		return nil, errors.New("name and symbol already has owner")
	}
	l.set(db, regKeyFn(name, symbol), ctx.contract.Caller().Hash())
	l.set(db, stateKeyFn(name, symbol), common.BytesToHash([]byte("reg")))
	return []byte("success"), nil
}

func (l *Tokennames) bind(ctx *PrecompiledContext, name, symbol, erc20addr []byte) ([]byte, error) {
	db := ctx.evm.StateDB
	caller := ctx.contract.Caller()
	name, symbol = nsFillFn(name, symbol)
	owner := l.get(db, regKeyFn(name, symbol))
	ownerAddr := common.BytesToAddress(owner.Bytes())
	if caller != ownerAddr {
		return nil, errors.New("Tokennames bind error ,found diff owner")
	}
	state := l.get(db, stateKeyFn(name, symbol))
	log.Info("Tokennames.bind",
		"state", string(state.Bytes()),
		"caller", ctx.contract.Caller().Hex(),
		"owner", owner.Hex(),
		"name", string(name),
		"symbol", string(symbol),
		"erc20addr", string(erc20addr),
		"value", ctx.contract.value)
	if state == l.emptyHash || state == common.BytesToHash([]byte("bind")) {
		return nil, errors.New("Tokennames bind error ,name and symbol was already bind.")
	}
	l.set(db, bindKeyFn(name, symbol), common.HexToAddress(string(erc20addr)).Hash())
	l.set(db, stateKeyFn(name, symbol), common.BytesToHash([]byte("bind")))
	return []byte("success"), nil
}

// return [owner,erc20addr] => [0:32],[32:]
func (l *Tokennames) whois(ctx *PrecompiledContext, name, symbol []byte) ([]byte, error) {
	if s := l.static.has(name, symbol); s != nil {
		return append(s.owner.Hash().Bytes(), s.erc20addr.Hash().Bytes()...), nil
	}
	db := ctx.evm.StateDB
	name, symbol = nsFillFn(name, symbol)
	ownerAddrHash := l.get(db, regKeyFn(name, symbol))
	log.Info("Tokennames.whois", "owner", ownerAddrHash.Hex(), "name", string(name), "symbol", string(symbol))
	if ownerAddrHash == l.emptyHash {
		return nil, fmt.Errorf("free name and symbol , whois (%s,%s)", name, symbol)
	}
	erc20addr := l.get(db, bindKeyFn(name, symbol))
	return append(ownerAddrHash.Bytes(), erc20addr.Bytes()...), nil
}

func (l *Tokennames) Run(ctx *PrecompiledContext, input []byte) ([]byte, error) {
	db := ctx.evm.StateDB
	if !db.Exist(TokennamesAddr) {
		db.CreateAccount(TokennamesAddr)
	}
	if db.GetCode(TokennamesAddr) == nil {
		db.SetCode(TokennamesAddr, TokennamesAddr.Bytes())
	}

	args := bytes.Split(input, []byte(","))
	from := ctx.contract.Caller()
	log.Info("Tokennames->", "from", from.Hex(), "args", args)
	switch string(args[0]) {
	case l.func_reg:
		if len(args) != 3 {
			return nil, errors.New("reg_args_error")
		}
		name, symbol := strings.ToLower(string(args[1])), strings.ToLower(string(args[2]))
		return l.reg(ctx, []byte(name), []byte(symbol))
	case l.func_bind:
		if len(args) != 4 {
			return nil, errors.New("bind_args_error")
		}
		name, symbol, erc20addr := strings.ToLower(string(args[1])), strings.ToLower(string(args[2])), args[3]
		return l.bind(ctx, []byte(name), []byte(symbol), erc20addr)
	case l.func_whois:
		if len(args) != 3 {
			return nil, errors.New("whois_args_error")
		}
		name, symbol := strings.ToLower(string(args[1])), strings.ToLower(string(args[2]))
		return l.whois(ctx, []byte(name), []byte(symbol))
	}
	return nil, errors.New("nothing_todo")
}
