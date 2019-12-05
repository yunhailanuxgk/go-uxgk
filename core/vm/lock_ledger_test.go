package vm

import (
	"encoding/hex"
	"github.com/yunhailanuxgk/go-uxgk/common"
	"testing"
)

func TestLockLedger_Run(t *testing.T) {
	/*
		lock,to,amount
		unlock,to,amount
		balance,addr
	*/
	lockArg := hex.EncodeToString([]byte("lock,0x0000000000000000000000000000000000000222,1000000000000000000000000000"))
	unlockArg := hex.EncodeToString([]byte("unlock,0x0000000000000000000000000000000000000222,1000000000000000000000000000"))
	balanceArg := hex.EncodeToString([]byte("balance,0x0000000000000000000000000000000000000222"))
	t.Log("addr", common.HexToAddress("0x111").Hex())
	t.Log("lock", lockArg)
	t.Log("unlock", unlockArg)
	t.Log("balance", balanceArg)

}
