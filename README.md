# UXGK

UXGK is an [Ethereum-compatible](https://github.com/ethereum/go-ethereum) project. It uses a new consensus and new block reward for UXGK ecosystem devices and IOT. And you can view the transactions on the [
BlockChain Browser Address](https://uxgk.pub).


Since the list of signers is 17, it is recommended that the confirmation number of general transfer transaction block be set to 17 (one round), and that of exchange block be set to 34 (two rounds).

## List of Chain ID's:
| Chain(s)    |  CHAIN_ID  | 
| ----------  | :-----------:| 
| mainnet     | 111            | 
| testnet     | 3            | 
| devnet      | 4            | 

## Warning

We suggest that the GasPrice should not be less than 18Gwei, otherwise the transaction may not be packaged into the block.

## Build the source 

Building UXGK requires both a Go (version 1.13.0 or later) and a C compiler. You can install them using your favourite package manager.

### MacOS & Linux

```
$ make uxgk
```

## Run node 

> By default will run on mainnet , add `--testnet` options to join the testnet

    $ ./build/bin/uxgk console
    
## Create new account
    Users can create new account:

    > personal.newAccount()

## Get your own miner id

    Every node has it's own miner id, you can run getMiner() function to get that id:

    > tribe.getMiner() 
    
## Bind your own miner id to wallet address

    Users can bind their miner ID to a wallet address:

    > tribe.bind("account","passwd") 
    
    Or Users can only generate binding signatures at the terminal:
    
    > tribe.bindSign("account") 

## Deposit uxgk for miner

    Users can become miner by deposit uxgk:

    > tribe.pocDeposit("account","passwd") 


## Start mining

    Users can start mining or resume it:

    > tribe.pocStart("account","passwd") 


## Stop mining

    Users can stop mining:

    > tribe.pocStop("account","passwd") 
    
## Withdraw uxgk

    Users can withdraw uxgk:

    > tribe.pocWithdraw("account","passwd")   
    
## More functions
    Users can input tribe to view:
    
    > tribe
    
## Security-related 
  
### Encrypt your nodekey

     $ ./build/bin/uxgk security --passwd
     
### Decrypt your nodekey

     $ ./build/bin/uxgk security --unlock
     

