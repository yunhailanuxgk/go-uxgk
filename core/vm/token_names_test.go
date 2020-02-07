package vm

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"github.com/yunhailanuxgk/go-uxgk/common"
	"github.com/yunhailanuxgk/go-uxgk/core/types"
	"github.com/yunhailanuxgk/go-uxgk/crypto"
	"github.com/yunhailanuxgk/go-uxgk/ethclient"
	"math/big"
	"testing"
)

func TestTokennames_Run(t *testing.T) {
	t.Log(tokennamesAddr.Hex())
	addr := common.HexToAddress(tokennamesAddr.Hex())
	t.Log(addr)
	addrH := common.BytesToHash(addr.Bytes())
	t.Log(addrH)
	addr2 := common.BytesToAddress(addrH.Bytes())
	t.Log(addr2)
}

func TestTokennames_Run2(t *testing.T) {
	t.Log(tokennamesAddr.Hex())
	data := []byte("reg,Hello,World")
	t.Log(string(data), hex.EncodeToString(data))
	data = []byte("whois,Hello,World")
	t.Log(string(data), hex.EncodeToString(data))
	data = []byte("withdarw")
	t.Log(string(data), hex.EncodeToString(data))
}

func TestReg(t *testing.T) {
	var (
		hexToPrv = func(h string) *ecdsa.PrivateKey {
			b, _ := hex.DecodeString(h)
			p, _ := crypto.ToECDSA(b)
			return p
		}
		prvToAddr = func(prv *ecdsa.PrivateKey) common.Address {
			return crypto.PubkeyToAddress(prv.PublicKey)
		}
		prvHex = "9ba390bbb0021693f30e2ba4e515feafbdefac3a52bcecd98282edbbb05f4194"
		prv    = hexToPrv(prvHex)
		cid    = big.NewInt(4)
		ctx    = context.Background()
	)
	client, err := ethclient.Dial("/Users/liangc/Library/uxgk/devnet/uxgk.ipc")
	if err != nil {
		panic(err)
	}
	fmt.Println("addr =", prvToAddr(prv).Hex())
	n, _ := client.PendingNonceAt(ctx, prvToAddr(prv))
	n99, _ := new(big.Int).SetString("99000000000000000000", 10)
	tx := types.NewTransaction(n, tokennamesAddr,
		n99, big.NewInt(100000), big.NewInt(3),
		[]byte("reg,foo,bar"))
	signer := types.NewEIP155Signer(cid)
	tx, _ = types.SignTx(tx, signer, prv)
	err = client.SendTransaction(ctx, tx)
	fmt.Println(err, tx.Hash().Hex())
}

func TestWithdarw(t *testing.T) {
	var (
		hexToPrv = func(h string) *ecdsa.PrivateKey {
			b, _ := hex.DecodeString(h)
			p, _ := crypto.ToECDSA(b)
			return p
		}
		prvToAddr = func(prv *ecdsa.PrivateKey) common.Address {
			return crypto.PubkeyToAddress(prv.PublicKey)
		}
		prvHex = "9ba390bbb0021693f30e2ba4e515feafbdefac3a52bcecd98282edbbb05f4194"
		prv    = hexToPrv(prvHex)
		cid    = big.NewInt(4)
		ctx    = context.Background()
	)
	client, err := ethclient.Dial("/Users/liangc/Library/uxgk/devnet/uxgk.ipc")
	if err != nil {
		panic(err)
	}
	fmt.Println("addr =", prvToAddr(prv).Hex())
	n, _ := client.PendingNonceAt(ctx, prvToAddr(prv))
	n99, _ := new(big.Int).SetString("0", 10)
	tx := types.NewTransaction(n, tokennamesAddr,
		n99, big.NewInt(100000), big.NewInt(3),
		[]byte("withdraw,0x0000000000000000000000000000000000000888"))
	signer := types.NewEIP155Signer(cid)
	tx, _ = types.SignTx(tx, signer, prv)
	err = client.SendTransaction(ctx, tx)
	fmt.Println(err, tx.Hash().Hex())
}
