// Copyright 2015 The UXGK Authors
// This file is part of the UXGK library.
//
// The UXGK library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The UXGK library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the UXGK library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"errors"
	"github.com/yunhailanuxgk/go-uxgk/common"
	"github.com/yunhailanuxgk/go-uxgk/consensus"
	"github.com/yunhailanuxgk/go-uxgk/consensus/misc"
	"github.com/yunhailanuxgk/go-uxgk/contracts/erc20token"
	"github.com/yunhailanuxgk/go-uxgk/core/state"
	"github.com/yunhailanuxgk/go-uxgk/core/types"
	"github.com/yunhailanuxgk/go-uxgk/core/vm"
	"github.com/yunhailanuxgk/go-uxgk/crypto"
	"github.com/yunhailanuxgk/go-uxgk/log"
	"github.com/yunhailanuxgk/go-uxgk/params"
	"math/big"
)

// StateProcessor is a basic Processor, which takes care of transitioning
// state from one point to another.
//
// StateProcessor implements Processor.
type StateProcessor struct {
	config *params.ChainConfig // Chain configuration options
	bc     *BlockChain         // Canonical block chain
	engine consensus.Engine    // Consensus engine used for block rewards
}

// NewStateProcessor initialises a new StateProcessor.
func NewStateProcessor(config *params.ChainConfig, bc *BlockChain, engine consensus.Engine) *StateProcessor {
	return &StateProcessor{
		config: config,
		bc:     bc,
		engine: engine,
	}
}

// Process processes the state changes according to the Ethereum rules by running
// the transaction messages using the statedb and applying any rewards to both
// the processor (coinbase) and any included uncles.
//
// Process returns the receipts and logs accumulated during the process and
// returns the amount of gas that was used in the process. If any of the
// transactions failed to execute due to insufficient gas it will return an error.
func (p *StateProcessor) Process(block *types.Block, statedb *state.StateDB, cfg vm.Config) (types.Receipts, []*types.Log, *big.Int, error) {
	var (
		receipts     types.Receipts
		totalUsedGas = big.NewInt(0)
		header       = block.Header()
		allLogs      []*types.Log
		gp           = new(GasPool).AddGas(block.GasLimit())
	)
	// Mutate the the block and state according to any hard-fork specs
	if p.config.DAOForkSupport && p.config.DAOForkBlock != nil && p.config.DAOForkBlock.Cmp(block.Number()) == 0 {
		misc.ApplyDAOHardFork(statedb)
	}
	// Iterate over and process the individual transactions
	for i, tx := range block.Transactions() {
		statedb.Prepare(tx.Hash(), block.Hash(), i)
		receipt, _, err := ApplyTransaction(p.config, p.bc, nil, gp, statedb, header, tx, totalUsedGas, cfg)
		if err != nil {
			return nil, nil, nil, err
		}
		receipts = append(receipts, receipt)
		allLogs = append(allLogs, receipt.Logs...)
	}
	// Finalize the block, applying any consensus engine specific extras (e.g. block rewards)
	p.engine.Finalize(p.bc, header, statedb, block.Transactions(), block.Uncles(), receipts)

	return receipts, allLogs, totalUsedGas, nil
}

// ApplyTransaction attempts to apply a transaction to the given state database
// and uses the input parameters for its environment. It returns the receipt
// for the transaction, gas used and an error if the transaction failed,
// indicating the block was invalid.
func ApplyTransaction(config *params.ChainConfig, bc *BlockChain, author *common.Address, gp *GasPool, statedb *state.StateDB, header *types.Header, tx *types.Transaction, usedGas *big.Int, cfg vm.Config) (*types.Receipt, *big.Int, error) {
	msg, err := tx.AsMessage(types.MakeSigner(config, header.Number))
	if err != nil {
		return nil, nil, err
	}
	// Create a new context to be used in the EVM environment
	context := NewEVMContext(msg, header, bc, author)
	// Create a new environment which holds all relevant information
	// about the transaction and calling mechanisms.
	vmenv := vm.NewEVM(context, statedb, config, cfg)
	// Apply the transaction to the current state (included in the env)
	_, gas, failed, err := ApplyMessage(vmenv, msg, gp, bc.currentBlock.Number())
	//showstate("2222", vmenv, tx.To(), err)
	if err != nil {
		return nil, nil, err
	}

	// add by linagc : 如果 to==nil 就是创建合约，此时判断是否为 erc20 合约
	if tx.To() == nil && len(tx.Data()) > 4 && erc20token.ERC20Trait.IsERC20(tx.Data()) {
		// TODO
		log.Info("TODO : ERC20 deploy , check name and symbol", "err",err,"failed", failed)
		log.Info("TODO : ERC20 deploy , check name and symbol", "err",err,"failed", failed)
		log.Info("TODO : ERC20 deploy , check name and symbol", "err",err,"failed", failed)
		log.Info("TODO : ERC20 deploy , check name and symbol", "err",err,"failed", failed)
	}

	if tx.To() != nil && params.IsChiefAddress(*tx.To()) && params.IsChiefUpdate(tx.Data()) && failed {
		return nil, nil, errors.New("chief_execute_fail")
	}

	//showstate("333333", vmenv, tx.To(), err)
	// Update the state with pending changes
	var root []byte
	if config.IsByzantium(header.Number) {
		statedb.Finalise(true)
		//showstate("4444444", vmenv, tx.To(), err)
	} else {
		root = statedb.IntermediateRoot(config.IsEIP158(header.Number)).Bytes()
		//showstate("55555555", vmenv, tx.To(), err)
	}
	//showstate("6666666", vmenv, tx.To(), err)
	// add by liangc
	if params.IsSIP001Block(bc.currentBlock.Number()) && tx.To() != nil && params.IsChiefAddress(*tx.To()) && params.IsChiefUpdate(tx.Data()) {
		log.Debug("⛽️ --> pay_back_chief_gas", "txid", tx.Hash().Hex(), "gas", gas)
		gp.AddGas(gas)
	} else {
		usedGas.Add(usedGas, gas)
	}
	// Create a new receipt for the transaction, storing the intermediate root and gas used by the tx
	// based on the eip phase, we're passing wether the root touch-delete accounts.
	// TODO may be error
	receipt := types.NewReceipt(root, failed, usedGas)
	receipt.TxHash = tx.Hash()
	// add by liangc : fit gaslimt
	if !(params.IsSIP001Block(bc.currentBlock.Number()) && tx.To() != nil && params.IsChiefAddress(*tx.To()) && params.IsChiefUpdate(tx.Data())) {
		receipt.GasUsed = new(big.Int).Set(gas)
	}
	// if the transaction created a contract, store the creation address in the receipt.
	if msg.To() == nil {
		receipt.ContractAddress = crypto.CreateAddress(vmenv.Context.Origin, tx.Nonce())
	}

	// Set the receipt logs and create a bloom for filtering
	receipt.Logs = statedb.GetLogs(tx.Hash())
	receipt.Bloom = types.CreateBloom(types.Receipts{receipt})
	return receipt, gas, err
}

//func showstate(flag string, evm *vm.EVM, to *common.Address, err error) {
//	if *to != common.HexToAddress("0x111") {
//		return
//	}
//	db := evm.StateDB
//	fmt.Println(flag, "show state ================>", err)
//	db.ForEachStorage(common.HexToAddress("0x111"), func(k, v common.Hash) bool {
//		fmt.Println("-->", k, v)
//		return true
//	})
//	fmt.Println(flag, "show state ================<", err)
//}
