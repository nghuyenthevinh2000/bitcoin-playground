package main

import (
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/btcsuite/btcd/blockchain"
	btcec "github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/chain"
	_ "github.com/btcsuite/btcwallet/walletdb/bdb"
)

type TestSuite struct {
	t                 *testing.T
	chainClient       *rpcclient.Client
	walletClient      *rpcclient.Client
	walletChainClient *chain.RPCClient
	btcdConnConfig    *rpcclient.ConnConfig
	btcdChainConfig   *chaincfg.Params
}

var (
	reg RegBitcoinProcess
)

const (
	ALICE_WALLET_SEED   = "4b92958dbc301dce528bb8aff445d00445c828220c287ec7d19599e3c256ce0e"
	BOB_WALLET_SEED     = "b8c646523dd3cbb5fecf3906604aa36bd0d556c7d81e8d138e56e62809a708c2"
	OLIVIA_WALLET_SEED  = "f9fdc67f82e763423c10448b33ec755c348cce8b58bebb19fdd25af5c9b49952"
	OMNIMAN_WALLET_SEED = "e7712cf15c5ae7e24ae85920abdd0fa11251096bfbe8bad2bfb0aacdd34f2c8a"
)

func TestMain(m *testing.M) {
	// start a bitcoin simnet network
	reg.RunBitcoinProcess(false)

	time.Sleep(3 * time.Second)

	// start a wallet process
	reg.RunWalletProcess()

	defer func() {
		// stop wallet process
		reg.StopWallet()
		// stop bitcoin process
		reg.StopBitcoin()
	}()

	// run all tests
	os.Exit(m.Run())
}

// go test -v -run ^TestRetrieveBlocks$ github.com/nghuyenthevinh2000/bitcoin-playground
func TestRetrieveBlocks(t *testing.T) {
	s := TestSuite{}
	s.setupSimNetSuite(t)

	// block 10
	hash, err := s.chainClient.GetBlockHash(10)
	assert.Nil(t, err)
	block_10, err := s.chainClient.GetBlock(hash)
	assert.Nil(t, err)

	// block 11
	hash, err = s.chainClient.GetBlockHash(11)
	assert.Nil(t, err)
	block_11, err := s.chainClient.GetBlock(hash)
	assert.Nil(t, err)

	assert.Equal(t, block_10.Header.BlockHash(), block_11.Header.PrevBlock)
}

// go test -v -run ^TestSeedString$ github.com/nghuyenthevinh2000/bitcoin-playground
func TestSeedString(t *testing.T) {
	suite := TestSuite{}
	suite.setupStaticSimNetSuite(t)

	for i := 0; i < 3; i++ {
		seed := suite.generateSeedString()
		t.Logf("seed: %s", seed)
	}
}

// go test -v -run ^TestBallGameContract$ github.com/nghuyenthevinh2000/bitcoin-playground
// the test is highly flaky, probably due to the fact that different processes are not synced.
// first run will always fail
// second run will always pass, but amount of alice is not updated
// third run will always fail, but amount of alice is updated
func TestBallGameContract(t *testing.T) {
	suite := TestSuite{}
	suite.setupSimNetSuite(t)

	// Alice, Bob wallet
	alice := suite.openWallet(t, ALICE_WALLET_SEED, "alice")
	bob := suite.openWallet(t, BOB_WALLET_SEED, "bob")

	// fund wallet if less than 0.1 BTC
	amt, err := alice.CalculateBalance(1)
	assert.Nil(t, err)
	if amt < btcutil.Amount(10000000) {
		suite.fundWallet(alice, btcutil.Amount(10000000))
	}

	amt, err = bob.CalculateBalance(1)
	assert.Nil(t, err)
	if amt < btcutil.Amount(10000000) {
		suite.fundWallet(bob, btcutil.Amount(10000000))
	}

	// alice initial balance
	amt, err = alice.CalculateBalance(1)
	assert.Nil(t, err)
	t.Logf("Alice balance: %d", amt)

	// Alice bets that VN wins
	// Bob bets that TL wins
	aliceWif := suite.exportWIFPriv(alice)
	bobWif := suite.exportWIFPriv(bob)
	witnessScriptCommitment, ballGameWitnessScript := suite.buildBallGameWitnessScript(aliceWif, bobWif)

	// create a P2WSH address
	address, err := btcutil.NewAddressWitnessScriptHash(witnessScriptCommitment[:], suite.btcdChainConfig)
	assert.Nil(t, err)
	t.Logf("P2SH address: %s", address.EncodeAddress())

	// witness script funding transaction
	commitHash, err := suite.walletClient.SendToAddress(address, btcutil.Amount(10000000))
	assert.Nil(t, err)

	// generate a block to confirm the transaction
	time.Sleep(3 * time.Second)
	suite.generateBlocks(1)

	// settle the bet through unlocking that witness script
	// if alice includes vn hash, then she can withdraw the funds
	// if bob includes tl hash, then he can withdraw the funds
	rawCommitTx, err := suite.chainClient.GetRawTransaction(commitHash)
	assert.Nil(t, err)

	t.Logf("Commitment tx: %+v", rawCommitTx.MsgTx())

	// create a new spending psbt
	aliceSpendPubScript := suite.buildSpendingPsbt(aliceWif)
	prevTxOut := rawCommitTx.MsgTx().TxOut[0]

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  *rawCommitTx.Hash(),
			Index: 0,
		},
	})
	txOut := wire.NewTxOut(1e3, aliceSpendPubScript)
	tx.AddTxOut(txOut)

	// constructing witness field
	inputFetcher := txscript.NewCannedPrevOutputFetcher(
		prevTxOut.PkScript,
		prevTxOut.Value,
	)
	// BIP0143 outlines a new hashing algorithm for the signature verification process
	// read more in knowledge/BIP0143.md
	// signing the transaction
	sigHashes := txscript.NewTxSigHashes(tx, inputFetcher)
	sig, err := txscript.RawTxInWitnessSignature(tx, sigHashes, 0, prevTxOut.Value, ballGameWitnessScript, txscript.SigHashSingle, aliceWif.PrivKey)
	assert.Nil(t, err)

	// add witness information to prove that alice has won the bet
	witness := wire.TxWitness{
		sig, aliceWif.SerializePubKey(), []byte("VN wins"), ballGameWitnessScript,
	}
	tx.TxIn[0].Witness = witness

	// check that this tx in is valid before sending
	blockUtxos := blockchain.NewUtxoViewpoint()
	sigCache := txscript.NewSigCache(50000)
	hashCache := txscript.NewHashCache(50000)

	blockUtxos.AddTxOut(btcutil.NewTx(rawCommitTx.MsgTx()), 0, 1)
	hashCache.AddSigHashes(tx, inputFetcher)

	err = blockchain.ValidateTransactionScripts(
		btcutil.NewTx(tx), blockUtxos, txscript.StandardVerifyFlags, sigCache, hashCache,
	)
	assert.Nil(t, err)

	// send the raw transaction
	_, err = suite.walletClient.SendRawTransaction(tx, false)
	assert.Nil(t, err)

	// generate a block to confirm the transaction
	time.Sleep(3 * time.Second)
	suite.generateBlocks(1)

	// check the balance of alice
	time.Sleep(3 * time.Second)
	amt, err = alice.CalculateBalance(1)
	assert.Nil(t, err)
	t.Logf("Alice balance: %d", amt)

	// test that after alice amount is higher than previous alice amount
}

func (s *TestSuite) setupRegNetSuite(t *testing.T) {
	s.t = t
	s.btcdChainConfig = &chaincfg.RegressionNetParams
	s.btcdChainConfig.DefaultPort = MockBtcdHost
}

func (s *TestSuite) setupStaticSimNetSuite(t *testing.T) {
	s.t = t
	s.btcdChainConfig = &chaincfg.SimNetParams
	s.btcdChainConfig.DefaultPort = MockBtcdHost
}

func (s *TestSuite) setupSimNetSuite(t *testing.T) {
	var err error

	s.t = t
	// connect to bitcoin btcd simnet network
	s.btcdConnConfig = &rpcclient.ConnConfig{
		Host:         MockBtcdHost,
		Endpoint:     "ws",
		User:         MockBtcUser,
		Pass:         MockBtcPass,
		HTTPPostMode: false,
		DisableTLS:   true,
	}
	s.btcdChainConfig = &chaincfg.SimNetParams
	s.btcdChainConfig.DefaultPort = MockBtcdHost
	// todo: determine what to do with bitcoin events for notification handlers
	s.chainClient, err = rpcclient.New(s.btcdConnConfig, nil)
	assert.Nil(t, err)

	// connect to bitcoin wallet simnet network
	s.walletChainClient, err = chain.NewRPCClientWithConfig(&chain.RPCClientConfig{
		Conn:  s.btcdConnConfig,
		Chain: s.btcdChainConfig,
	})
	assert.Nil(t, err)
	// start socket connection
	err = s.walletChainClient.Start()
	assert.Nil(t, err)

	// open main wallet
	walletConnConfig := &rpcclient.ConnConfig{
		Host:         MockWalletHost,
		Endpoint:     "ws",
		User:         MockBtcUser,
		Pass:         MockBtcPass,
		HTTPPostMode: false,
		DisableTLS:   true,
	}
	s.walletClient, err = rpcclient.New(walletConnConfig, nil)
	assert.Nil(t, err)

	// open wallet for 10 mins
	err = s.walletClient.WalletPassphrase(MockWalletPass, 10*60)
	assert.Nil(t, err)
}

func (s *TestSuite) bytesToHexStr(b []byte) string {
	return hex.EncodeToString(b)
}

// this is for deriving witness pubkey hash from public key
func (s *TestSuite) deriveWitnessPubkeyHash(wif *btcutil.WIF) string {
	pubKey := wif.SerializePubKey()
	pubKeyHash := btcutil.Hash160(pubKey)
	witness, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, s.btcdChainConfig)
	assert.Nil(s.t, err)
	return witness.EncodeAddress()
}

func (s *TestSuite) generateBlocks(num uint32) {
	_, err := s.chainClient.Generate(num)
	assert.Nil(s.t, err)
}

func (s *TestSuite) generateSeed() []byte {
	seed, err := hdkeychain.GenerateSeed(hdkeychain.RecommendedSeedLen)
	assert.Nil(s.t, err)
	return seed
}

func (s *TestSuite) generate32BSeed() [hdkeychain.RecommendedSeedLen]byte {
	var res [hdkeychain.RecommendedSeedLen]byte
	seed, err := hdkeychain.GenerateSeed(hdkeychain.RecommendedSeedLen)
	assert.Nil(s.t, err)
	copy(res[:], seed)
	return res
}

func (s *TestSuite) generateSeedString() string {
	seed := s.generateSeed()
	return hex.EncodeToString(seed[:])
}

type KeyPair struct {
	pub  *btcec.PublicKey
	priv *btcec.PrivateKey
}

func (s *TestSuite) newKeyPair(seed string) ([]byte, KeyPair) {
	var seedBytes []byte

	if seed == "" {
		seedBytes = s.generateSeed()
	} else {
		var err error
		seedBytes, err = hex.DecodeString(seed)
		assert.Nil(s.t, err)
	}

	hd, err := hdkeychain.NewMaster(seedBytes, s.btcdChainConfig)
	assert.Nil(s.t, err)
	pub, err := hd.ECPubKey()
	assert.Nil(s.t, err)
	priv, err := hd.ECPrivKey()
	assert.Nil(s.t, err)

	return seedBytes, KeyPair{pub, priv}
}

func (s *TestSuite) convertPrivKeyToWIF(priv *btcec.PrivateKey) string {
	wif, err := btcutil.NewWIF(priv, s.btcdChainConfig, true)
	assert.Nil(s.t, err)

	return wif.String()
}

// validate script creates a funding transaction and a spending transaction
// the funding transaction will send funds to the test script
// the spending transaction will spend the funds from the funding transaction with test witness
func (s *TestSuite) validateScript(pkScript []byte, blockHeight int32, witnessFunc func(t *testing.T, prevOut *wire.TxOut, tx *wire.MsgTx, sigHashes *txscript.TxSigHashes, idx int) wire.TxWitness) {
	// create a random key pair
	_, keypair := s.newKeyPair("")

	// create a first random funding transaction to a pubkey
	txHash, err := chainhash.NewHashFromStr("aff48a9b83dc525d330ded64e1b6a9e127c99339f7246e2c89e06cd83493af9b")
	assert.Nil(s.t, err)
	// create tx
	tx_1 := wire.NewMsgTx(2)
	tx_1.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  *txHash,
			Index: uint32(0),
		},
	})

	txOut := &wire.TxOut{
		Value: 1000000000, PkScript: pkScript,
	}
	tx_1.AddTxOut(txOut)

	sig, err := txscript.SignatureScript(tx_1, 0, []byte{}, txscript.SigHashDefault, keypair.priv, true)
	assert.Nil(s.t, err)
	tx_1.TxIn[0].SignatureScript = sig

	// create a second spending transaction where the signature is verified against the pubkey
	tx_2 := wire.NewMsgTx(2)
	tx_2.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  tx_1.TxHash(),
			Index: uint32(0),
		},
	})

	txOut = &wire.TxOut{
		Value: 1000000000, PkScript: nil,
	}
	tx_2.AddTxOut(txOut)
	tx_2.LockTime = uint32(blockHeight)

	inputFetcher := txscript.NewCannedPrevOutputFetcher(
		tx_1.TxOut[0].PkScript,
		tx_1.TxOut[0].Value,
	)
	sigHashes := txscript.NewTxSigHashes(tx_2, inputFetcher)

	witness := witnessFunc(s.t, tx_1.TxOut[0], tx_2, sigHashes, 0)
	tx_2.TxIn[0].Witness = witness

	// check that this tx in is valid before sending
	blockUtxos := blockchain.NewUtxoViewpoint()
	sigCache := txscript.NewSigCache(50000)
	hashCache := txscript.NewHashCache(50000)

	blockUtxos.AddTxOut(btcutil.NewTx(tx_1), 0, blockHeight)
	hashCache.AddSigHashes(tx_2, inputFetcher)

	err = blockchain.ValidateTransactionScripts(
		btcutil.NewTx(tx_2), blockUtxos, txscript.StandardVerifyFlags, sigCache, hashCache,
	)
	assert.Nil(s.t, err)
}
