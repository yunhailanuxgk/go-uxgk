package vm

import (
	"errors"
	"fmt"
	"github.com/yunhailanuxgk/go-uxgk/common"
	"github.com/yunhailanuxgk/go-uxgk/crypto"
	"github.com/yunhailanuxgk/go-uxgk/params"
	"math/big"
)

var destroyAddr = common.HexToAddress("0x")

type destroy struct {
	logk common.Hash
}

func (d destroy) RequiredGas(ctx *PrecompiledContext, input []byte) uint64 {
	if common.EmptyHash(d.logk) {
		d.logk = common.BytesToHash(crypto.Keccak256([]byte("logkey")))
	}
	return 21000
}

func (d destroy) getlog(db StateDB) *big.Int {
	l := new(big.Int).SetBytes(db.GetState(destroyAddr, d.logk).Bytes())
	fmt.Println("destroy.getlog >>>", l)
	return l
}

func (d destroy) putlog(db StateDB, sub *big.Int) {
	fmt.Println("destroy.putlog >>>", sub)
	v := db.GetState(destroyAddr, d.logk)
	a := new(big.Int).SetBytes(v.Bytes())
	b := new(big.Int).Add(a, sub)
	db.SetState(destroyAddr, d.logk, common.BytesToHash(b.Bytes()))
}

func (d destroy) Run(ctx *PrecompiledContext, input []byte) ([]byte, error) {
	fmt.Println("destroy >>>", "blk", ctx.evm.BlockNumber, "val", ctx.contract.Value())
	if params.IsUIP002Block(ctx.evm.BlockNumber) {
		db := ctx.evm.StateDB
		if !db.Exist(destroyAddr) {
			db.CreateAccount(destroyAddr)
		}
		if db.GetCode(destroyAddr) == nil {
			db.SetCode(destroyAddr, destroyAddr.Bytes())
		}
		if len(input) > 0 {
			if ctx.contract.Value().Cmp(big.NewInt(0)) > 0 {
				return nil, errors.New("intput nil to destroy coins")
			}
			l := d.getlog(db)
			return l.Bytes(), nil
		} else {
			sub := db.GetBalance(destroyAddr)
			db.SubBalance(destroyAddr, sub)
			d.putlog(db, sub)
		}
		return nil, nil
	}
	return nil, errors.New("execute destroy must after UIP002")
}
