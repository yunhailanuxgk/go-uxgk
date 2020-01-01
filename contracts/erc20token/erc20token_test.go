package erc20token

import (
	"encoding/hex"
	"math/big"
	"github.com/yunhailanuxgk/go-uxgk/common"
	"github.com/yunhailanuxgk/go-uxgk/crypto"
	"testing"
)

func TestErc20Token(t *testing.T) {
	var (
		_initialSupply, _ = new(big.Int).SetString("10000000000000000000", 10)
		_name             = "HelloWorld"
		_symbol           = "HWT"
		_decimals         = big.NewInt(18)
	)
	rcode, err := Template.Compile(_initialSupply, _name, _symbol, _decimals)
	t.Log(err, len(rcode), Template.codeLen)
	h := hex.EncodeToString(rcode)
	t.Log(h)
	t.Log(Template.codeHash.Hex())
	a := hex.EncodeToString(crypto.Keccak256(Template.codeByte[:]))
	b := hex.EncodeToString(crypto.Keccak256(Template.codeByte[:11075]))
	c := common.BytesToHash(crypto.Keccak256(Template.codeByte[:]))
	d := common.BytesToHash(crypto.Keccak256(Template.codeByte[:11075]))

	e := crypto.Keccak256Hash(Template.codeByte[:])
	t.Log("->",a, b)
	t.Log("->",c.Hex(), d.Hex())
	t.Log("-->",e.Hex())
	err = Template.VerifyCode(rcode)
	t.Log("verifyCode", err)
}
