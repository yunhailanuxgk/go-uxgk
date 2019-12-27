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
 * @Time   : 2019/12/25 7:41 下午
 * @Author : liangc
 *************************************************************************/

package erc20token

import (
	"encoding/hex"
	"math/big"
	"pdx-chain/common"
	"pdx-chain/crypto"
	"testing"
)

func TestErc20Token(t *testing.T) {
	var (
		_initialSupply, _ = new(big.Int).SetString("10000000000000000000", 10)
		_name             = "HelloWorld"
		_symbol           = "HWT"
		_decimals         = big.NewInt(18)
	)
	//----------------vvvvvvvvvvvvvvvvvvvvvvvvvvvv----------------> 11900 0x11e64a43cbfd4196b857465cc4c08a041d3e2c4e46a3df4d167c0a0573d88600
	//---------appendReg--> 0x7D8f6f67f44A60C803e56D69decDE47eBd4d1a28 11075 code too short
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
