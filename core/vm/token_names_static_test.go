package vm

import (
	"context"
	"fmt"
	ethereum "github.com/yunhailanuxgk/go-uxgk"
	"github.com/yunhailanuxgk/go-uxgk/common"
	"github.com/yunhailanuxgk/go-uxgk/contracts/erc20token"
	"github.com/yunhailanuxgk/go-uxgk/core/types"
	"github.com/yunhailanuxgk/go-uxgk/ethclient"
	"io/ioutil"
	"math/big"
	"testing"
	"time"
)

func TestFindErc20(t *testing.T) {
	ctx := context.Background()
	signer := types.NewEIP155Signer(big.NewInt(111))
	template := `newstaticName("%s","%s","%s","%s"),`
	client, err := ethclient.Dial("/Users/liangc/Library/uxgk/uxgk.ipc")
	if err != nil {
		t.Error(err)
		return
	}
	current, err := client.BlockByNumber(ctx, nil)
	if err != nil {
		return
	}
	t.Log(current.Number(), current)
	s := time.Now()
	fmt.Println("start.")
	output := make([]byte, 0)
	for i := current.Number(); i.Cmp(big.NewInt(0)) > 279489; i = new(big.Int).Sub(i, big.NewInt(1)) {
		blk, _ := client.BlockByNumber(ctx, i)
		for _, tx := range blk.Transactions() {
			if tx.To() == nil && erc20token.ERC20Trait.IsERC20(tx.Data()) {
				r, _ := client.TransactionReceipt(ctx, tx.Hash())
				erc20addr := r.ContractAddress
				from, _ := types.Sender(signer, tx)
				nameData, _ := client.CallContract(ctx, ethereum.CallMsg{From: from, To: &erc20addr, Data: erc20token.ERC20Trait.SigOfName()}, nil)
				symbolData, _ := client.CallContract(ctx, ethereum.CallMsg{From: from, To: &erc20addr, Data: erc20token.ERC20Trait.SigOfSymbol()}, nil)
				name, _ := erc20token.ERC20Trait.DecodeOutput("name", nameData)
				symbol, _ := erc20token.ERC20Trait.DecodeOutput("symbol", symbolData)
				//fmt.Println("TOKEN==>", "num", blk.Number(), "tx", tx.Hash().Hex(), "from", from.Hex(), "erc20addr", erc20addr.Hex(), "name", name, "symbol", symbol)
				//newstaticName("name","symbol","owner","erc20addr")
				row := fmt.Sprintf(template, name, symbol, from.Hex(), erc20addr.Hex())
				fmt.Println(tx.Hash().Hex(), row)
				output = append(output, []byte(row)...)
				output = append(output, []byte("\r\n")...)
			}
		}
	}
	err = ioutil.WriteFile("/tmp/sl.txt", output, 0755)
	fmt.Println("success.", "err", err, "timeused", time.Since(s), "total", current.Number(), "output", "/tmp/sl.txt")

}

func TestFind(t *testing.T) {
	ctx := context.Background()
	client, err := ethclient.Dial("/Users/liangc/Library/uxgk/uxgk.ipc")
	if err != nil {
		t.Error(err)
		return
	}
	tx, _, _ := client.TransactionByHash(ctx, common.HexToHash("0x160093382cccafa10667f9608b121544db3cd4a8ab5a3049ed002d5cb8c04753"))
	fmt.Println(tx.To(), tx)
}
