package params

import (
	"github.com/yunhailanuxgk/go-uxgk/common"
	"math/big"
	"sort"
	"sync"
	"testing"
)

var data = ChiefInfoList{
}

func TestChiefInfoList(t *testing.T) {
	t.Log(data)
	sort.Sort(data)
	t.Log(data)
}

func TestGetChiefAddress(t *testing.T) {
	sort.Sort(data)
	t.Log(getChiefInfo(data, big.NewInt(5)))
	t.Log(getChiefInfo(data, big.NewInt(50010)))
	t.Log(getChiefInfo(data, big.NewInt(20010)))
	t.Log(getChiefInfo(data, big.NewInt(30000)))
	t.Log(getChiefInfo(data, big.NewInt(40010)))
	t.Log(getChiefInfo(data, big.NewInt(80000)))
}

func TestIsChiefAddress(t *testing.T) {
	t.Log(isChiefAddress(data, common.HexToAddress("0x04")))
	t.Log(isChiefAddress(data, common.HexToAddress("0x0f")))
}

type ChiefStatus1 struct {
	NumberList []*big.Int
	BlackList  []*big.Int
}

type ChiefStatus2 struct {
	NumberList []*big.Int
	BlackList  []*big.Int
}

func TestFooBar(t *testing.T) {
	a := ChiefStatus1{[]*big.Int{big.NewInt(1)}, []*big.Int{big.NewInt(2)}}
	t.Log(a)
	b := ChiefStatus2(a)
	t.Log(b)
	var x []common.Address
	x = nil
	t.Log(x == nil)
}

func TestIsChiefUpdate(t *testing.T) {
	data := []byte{28, 27, 135, 114, 0, 0}
	t.Log(IsChiefUpdate(data))
	t.Log(IsChiefUpdate(data))
	t.Log(IsChiefUpdate(data))
	data = []byte{28, 27, 135, 115, 0, 0}
	t.Log(IsChiefUpdate(data))

}

func TestAddr(t *testing.T) {
	add1 := common.HexToAddress("0xAd4c80164065a3c33dD2014908c7563eFf88aB49")
	add2 := common.HexToAddress("0xAd4c80164065a3c33dD2014908c7563eFf88Ab49")
	t.Log(add1 == add2)
}
/*
func TestRegisterContract(t *testing.T) {
	t.Log(chieflib.TribeChief_1_0_0ABI)
	hexdata := "1c1b87720000000000000000000000000000000000000000000000000000000000000000"
	data, err := hex.DecodeString(hexdata)
	t.Log("1 err=", err, data)
	_abi, err := abi.JSON(strings.NewReader(chieflib.TribeChief_1_0_0ABI))
	t.Log("2 err=", err)
	method := _abi.Methods["update"]
	id := new(common.Address)
	r := []interface{}{id}
	t.Log(len(data[4:]), len(data), data[:4])
	err = method.Inputs.Unpack(id, data[4:])
	t.Log("4 err=", err, r, id.Hex())

	t.Log(bytes.Equal(data[:4], []byte{28, 27, 135, 114}), data[:4])

	rrr, _ := _abi.Pack("update", common.HexToAddress("0xAd4c80164065a3c33dD2014908c7563eFf88Ab49"))
	t.Log(rrr[4:])
	aaa := common.Bytes2Hex(rrr[4:])
	t.Log(common.HexToAddress(aaa) == common.HexToAddress("0xAd4c80164065a3c33dD2014908c7563eFf88Ab49"))
	bbb := common.Bytes2Hex([]byte{0, 0, 0, 0, 0, 0, 0})
	t.Log(common.HexToAddress(bbb) == common.HexToAddress(""))
}
*/
func TestError(t *testing.T) {
	ch := make(chan int)
	sm := new(sync.Map)
	sm.Store("foo", "bar")
	sm.Store("hello", "world")

	sm.Range(func(k, v interface{}) bool {
		defer func() {
			if err := recover(); err != nil {
				t.Log(k, v, "err:", err)
			}
		}()
		defer close(ch)
		t.Log(k, v)
		return true
	})

}
