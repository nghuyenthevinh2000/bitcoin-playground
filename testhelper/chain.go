package testhelper

import (
	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
)

// this section is available if static suite is setup
// TODO: look at mempool/mempool_test.go to see how to setup a synthetic chain

func (s *TestSuite) GenerateNextBlock(block *btcutil.Block) {
	if s.Blockchain == nil {
		panic("synthetic blockchain is not initialized")
	}

	s.Blockchain.ProcessBlock(block, blockchain.BFNone)
}

// create an account
// fund that account with CoinBase tranasction
func (s *TestSuite) CreateAccountWithFunds(address string, amount btcutil.Amount) {
	if s.Blockchain == nil {
		panic("synthetic blockchain is not initialized")
	}

	// create a coinbase transaction
}
