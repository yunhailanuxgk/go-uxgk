package vm

import (
	"bytes"
	"errors"
	"github.com/yunhailanuxgk/go-uxgk/common"
	"github.com/yunhailanuxgk/go-uxgk/crypto"
	"github.com/yunhailanuxgk/go-uxgk/log"
	"math/big"
)

const (
	func_lock    = "lock"
	func_unlock  = "unlock"
	func_balance = "balance"
)

var (
	LockLedgerAddr = common.HexToAddress("0x111")

	get = func(db StateDB, k common.Hash) common.Hash {
		v := db.GetState(LockLedgerAddr, k)
		//fmt.Println("lock_ledger.go::get", "k", k, "v", v)
		return v
	}
	set = func(db StateDB, k, v common.Hash) {
		//fmt.Println("lock_ledger.go::set", "k", k, "v", v)
		db.SetState(LockLedgerAddr, k, v)
	}

	owner = func(from, to common.Address) common.Hash {
		return common.BytesToHash(crypto.Keccak256(from.Hash().Bytes(), to.Hash().Bytes()))
	}
)

type LockLedger struct{}

func (l *LockLedger) RequiredGas(input []byte) uint64 {
	return 0
}

//
func (l *LockLedger) balance(ctx *PrecompiledContext, addr common.Address) ([]byte, error) {
	h := get(ctx.evm.StateDB, addr.Hash())
	b := new(big.Int).SetBytes(h.Bytes())
	log.Info("LockLedger.balance", "addr", addr.Hex(), "balance", b)
	return h.Bytes(), nil
}

func (l *LockLedger) lock(ctx *PrecompiledContext, from, to common.Address, amount *big.Int) ([]byte, error) {
	log.Info("LockLedger.lock", "from", from.Hex(), "to", to.Hex(), "amount", amount)
	db := ctx.evm.StateDB
	balance := db.GetBalance(from)
	if balance.Cmp(amount) < 0 {
		return nil, errors.New("balance too low")
	}
	db.SubBalance(from, amount)
	set(db, owner(from, to), from.Hash())

	preH := get(db, to.Hash())
	preAmount := new(big.Int).SetBytes(preH.Bytes())
	finalAmount := new(big.Int).Add(preAmount, amount)
	if len(finalAmount.Bytes()) > 32 {
		return nil, errors.New("amount too big")
	}
	set(db, to.Hash(), common.BytesToHash(finalAmount.Bytes()))
	return nil, nil
}

func (l *LockLedger) unlock(ctx *PrecompiledContext, from, to common.Address, amount *big.Int) ([]byte, error) {
	db := ctx.evm.StateDB
	f := get(db, owner(from, to))
	log.Info("LockLedger.unlock", "from", from.Hex(), "to", to.Hex(), "amount", amount, "owner", f.Hex())
	if f != from.Hash() {
		return nil, errors.New("error owner")
	}
	preH := get(db, to.Hash())
	preAmount := new(big.Int).SetBytes(preH.Bytes())
	if preAmount.Cmp(amount) < 0 {
		return nil, errors.New("preAmount too low")
	}
	finalAmount := new(big.Int).Sub(preAmount, amount)
	set(db, to.Hash(), common.BytesToHash(finalAmount.Bytes()))
	db.AddBalance(to, amount)
	return nil, nil
}

/*
lock,to,amount
unlock,to,amount
balance,addr
*/

func (l *LockLedger) Run(ctx *PrecompiledContext, input []byte) ([]byte, error) {
	//addr := ctx.contract.CodeAddr
	//fmt.Println("==== LockLedger::Run ====>", LockLedgerAddr.Hex(), addr.Hex(), db.Exist(*addr))
	db := ctx.evm.StateDB
	if !db.Exist(LockLedgerAddr) {
		db.CreateAccount(LockLedgerAddr)
	}
	if db.GetCode(LockLedgerAddr) == nil {
		db.SetCode(LockLedgerAddr, LockLedgerAddr.Bytes())
	}

	args := bytes.Split(input, []byte(","))
	from := ctx.contract.Caller()
	switch string(args[0]) {
	case func_lock:
		toB := args[1]
		amountB := args[2]
		a, _ := new(big.Int).SetString(string(amountB), 10)
		return l.lock(ctx, from, common.HexToAddress(string(toB)), a)
	case func_unlock:
		toB := args[1]
		amountB := args[2]
		a, _ := new(big.Int).SetString(string(amountB), 10)
		return l.unlock(ctx, from, common.HexToAddress(string(toB)), a)
	case func_balance:
		return l.balance(ctx, common.HexToAddress(string(args[1])))
	}
	return nil, errors.New("nothing_todo")
}
