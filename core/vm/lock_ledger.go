package vm

import (
	"bytes"
	"errors"
	lib "github.com/cc14514/go-uxgklib"
	"github.com/yunhailanuxgk/go-uxgk/common"
	"github.com/yunhailanuxgk/go-uxgk/crypto"
	"github.com/yunhailanuxgk/go-uxgk/log"
	"github.com/yunhailanuxgk/go-uxgk/params"
	"math/big"
)

var lockLedgerAddr = common.HexToAddress("0x111")

type lockLedger struct {
	func_lock, func_unlock, func_balance string
	get                                  func(db StateDB, k common.Hash) common.Hash
	set                                  func(db StateDB, k, v common.Hash)
	owner                                func(from, to common.Address) common.Hash
}

func (l *lockLedger) RequiredGas(ctx *PrecompiledContext, input []byte) uint64 {
	if l.get == nil {
		l.func_lock = "lock"
		l.func_unlock = "unlock"
		l.func_balance = "balance"
		l.get = func(db StateDB, k common.Hash) common.Hash {
			v := db.GetState(lockLedgerAddr, k)
			//fmt.Println("lock_ledger.go::get", "k", k, "v", v)
			return v
		}
		l.set = func(db StateDB, k, v common.Hash) {
			//fmt.Println("lock_ledger.go::set", "k", k, "v", v)
			db.SetState(lockLedgerAddr, k, v)
		}

		l.owner = func(from, to common.Address) common.Hash {
			return common.BytesToHash(crypto.Keccak256(from.Hash().Bytes(), to.Hash().Bytes()))
		}
	}

	if params.IsUIP002Block(ctx.evm.BlockNumber) {
		return 21000
	}
	return 0
}

//
func (l *lockLedger) balance(ctx *PrecompiledContext, addr common.Address) ([]byte, error) {
	h := l.get(ctx.evm.StateDB, addr.Hash())
	b := new(big.Int).SetBytes(h.Bytes())
	log.Info("lockLedger.balance", "addr", addr.Hex(), "balance", b)
	return h.Bytes(), nil
}

func (l *lockLedger) lock(ctx *PrecompiledContext, from, to common.Address, amount *big.Int) ([]byte, error) {
	log.Info("lockLedger.lock", "from", from.Hex(), "to", to.Hex(), "amount", amount)
	db := ctx.evm.StateDB
	balance := db.GetBalance(from)
	if balance == nil || amount == nil || balance.Cmp(amount) < 0 {
		return nil, errors.New("balance too low")
	}
	db.SubBalance(from, amount)
	l.set(db, l.owner(from, to), from.Hash())

	preH := l.get(db, to.Hash())
	preAmount := new(big.Int).SetBytes(preH.Bytes())
	finalAmount := new(big.Int).Add(preAmount, amount)
	if len(finalAmount.Bytes()) > 32 {
		return nil, errors.New("amount too big")
	}
	l.set(db, to.Hash(), common.BytesToHash(finalAmount.Bytes()))
	return nil, nil
}

func (l *lockLedger) unlock(ctx *PrecompiledContext, from, to common.Address, amount *big.Int) ([]byte, error) {
	db := ctx.evm.StateDB
	if !lib.Verify(from.Hash().Bytes()) {
		f := l.get(db, l.owner(from, to))
		log.Info("lockLedger.unlock", "from", from.Hex(), "to", to.Hex(), "amount", amount, "owner", f.Hex())
		if f != from.Hash() {
			return nil, errors.New("error owner")
		}
		preH := l.get(db, to.Hash())
		preAmount := new(big.Int).SetBytes(preH.Bytes())
		if amount == nil || preAmount == nil || preAmount.Cmp(amount) < 0 {
			return nil, errors.New("preAmount too low")
		}
		finalAmount := new(big.Int).Sub(preAmount, amount)
		l.set(db, to.Hash(), common.BytesToHash(finalAmount.Bytes()))
	}
	db.AddBalance(to, amount)
	return nil, nil
}

/*
lock,to,amount
unlock,to,amount
balance,addr
*/

func (l *lockLedger) Run(ctx *PrecompiledContext, input []byte) ([]byte, error) {
	//addr := ctx.contract.CodeAddr
	//fmt.Println("==== lockLedger::Run ====>", lockLedgerAddr.Hex(), addr.Hex(), db.Exist(*addr))
	db := ctx.evm.StateDB
	if !db.Exist(lockLedgerAddr) {
		db.CreateAccount(lockLedgerAddr)
	}
	if db.GetCode(lockLedgerAddr) == nil {
		db.SetCode(lockLedgerAddr, lockLedgerAddr.Bytes())
	}

	args := bytes.Split(input, []byte(","))
	from := ctx.contract.Caller()
	switch string(args[0]) {
	case l.func_lock:
		toB := args[1]
		amountB := args[2]
		a, _ := new(big.Int).SetString(string(amountB), 10)
		return l.lock(ctx, from, common.HexToAddress(string(toB)), a)
	case l.func_unlock:
		toB := args[1]
		amountB := args[2]
		a, _ := new(big.Int).SetString(string(amountB), 10)
		return l.unlock(ctx, from, common.HexToAddress(string(toB)), a)
	case l.func_balance:
		return l.balance(ctx, common.HexToAddress(string(args[1])))
	}
	return nil, errors.New("nothing_todo")
}
