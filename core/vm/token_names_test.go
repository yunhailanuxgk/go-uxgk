package vm

import (
	"encoding/hex"
	"github.com/yunhailanuxgk/go-uxgk/common"
	"testing"
)

func TestTokennames_Run(t *testing.T) {
	addr := common.HexToAddress(TokennamesAddr.Hex())
	t.Log(addr)
	addrH := common.BytesToHash(addr.Bytes())
	t.Log(addrH)
	addr2 := common.BytesToAddress(addrH.Bytes())
	t.Log(addr2)
}

func TestTokennames_Run2(t *testing.T) {
	t.Log(TokennamesAddr.Hex())
	data := []byte("reg,Hello,World")
	t.Log(string(data), hex.EncodeToString(data))
	data = []byte("whois,Hello,World")
	t.Log(string(data), hex.EncodeToString(data))
}
