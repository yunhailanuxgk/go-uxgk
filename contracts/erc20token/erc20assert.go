package erc20token

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/yunhailanuxgk/go-uxgk/accounts/abi"
	"regexp"
	"strings"
)

// https://eips.ethereum.org/EIPS/eip-20
/* ------------- trait dict ---------------
name()
symbol()
decimals()
totalSupply()
balanceOf(address)
transfer(address,uint256)
approve(address,uint256)
transferFrom(address,address,uint256)
allowance(address,address)
*/
var ERC20Trait = newErc20trait()
var EIP20InterfaceABI = "[{\"constant\":true,\"inputs\":[],\"name\":\"name\",\"outputs\":[{\"name\":\"\",\"type\":\"string\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"_spender\",\"type\":\"address\"},{\"name\":\"_value\",\"type\":\"uint256\"}],\"name\":\"approve\",\"outputs\":[{\"name\":\"success\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"totalSupply\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"_from\",\"type\":\"address\"},{\"name\":\"_to\",\"type\":\"address\"},{\"name\":\"_value\",\"type\":\"uint256\"}],\"name\":\"transferFrom\",\"outputs\":[{\"name\":\"success\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"decimals\",\"outputs\":[{\"name\":\"\",\"type\":\"uint8\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"_owner\",\"type\":\"address\"}],\"name\":\"balanceOf\",\"outputs\":[{\"name\":\"balance\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"symbol\",\"outputs\":[{\"name\":\"\",\"type\":\"string\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"_to\",\"type\":\"address\"},{\"name\":\"_value\",\"type\":\"uint256\"}],\"name\":\"transfer\",\"outputs\":[{\"name\":\"success\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"_owner\",\"type\":\"address\"},{\"name\":\"_spender\",\"type\":\"address\"}],\"name\":\"allowance\",\"outputs\":[{\"name\":\"remaining\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"}]"

type erc20trait struct {
	funcdict map[string][]byte
	erc20abi abi.ABI
}

func newErc20trait() *erc20trait {
	abi, err := abi.JSON(strings.NewReader(EIP20InterfaceABI))
	if err != nil {
		panic(err)
	}
	return &erc20trait{map[string][]byte{
		"name()":                                {6, 253, 222, 3},
		"symbol()":                              {149, 216, 155, 65},
		"decimals()":                            {49, 60, 229, 103},
		"totalSupply()":                         {24, 22, 13, 221},
		"balanceOf(address)":                    {112, 160, 130, 49},
		"allowance(address,address)":            {221, 98, 237, 62},
		"transfer(address,uint256)":             {169, 5, 156, 187},
		"approve(address,uint256)":              {9, 94, 167, 179},
		"transferFrom(address,address,uint256)": {35, 184, 114, 221}}, abi}
}

// 判断传入 code 是否符合 erc20 标准
// https://eips.ethereum.org/EIPS/eip-20
func (self *erc20trait) IsERC20(code []byte) bool {
	if code == nil || len(code) < 5 {
		return false
	}
	for sigs, sigb := range self.funcdict {
		if !bytes.Contains(code, sigb[:]) {
			fmt.Println("create contract", "erc20", false, "not_found_sig=", sigs)
			return false
		}
	}
	return true
}

// 公司名称的方法签名，记录名称，例如：Tether USD
func (self *erc20trait) SigOfName() []byte { return self.funcdict["name()"] }

// Token 名称的方法签名，记录Token名，例如：USDT
func (self *erc20trait) SigOfSymbol() []byte { return self.funcdict["symbol()"] }

func (self *erc20trait) DecodeOutput(method string, output []byte) (interface{}, error) {
	var o interface{}
	err := self.erc20abi.Unpack(&o, method, output)
	return o, err
}

func (self *erc20trait) VerifyName(name string) error {
	ok, err := regexp.MatchString(`^[a-zA-Z0-9]{3,20}$`, string(name))
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("erc20 name format error")
	}
	return nil
}

func (self *erc20trait) VerifySymbol(symbol string) error {
	ok, err := regexp.MatchString(`^[a-zA-Z0-9]{1,12}$`, string(symbol))
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("erc20 symbol format error")
	}
	return nil
}
