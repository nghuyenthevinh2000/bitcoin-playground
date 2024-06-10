package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/btcsuite/btcwallet/walletdb"
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

// go test -v -run ^TestSeedString$ github.com/nghuyenthevinh2000/bitcoin-playground
func TestSeedString(t *testing.T) {
	suite := TestSuite{}
	suite.setupSuite(t)

	seed := suite.generateSeedString()
	t.Logf("seed: %s", seed)
}

// go test -v -run ^TestBtcdCreateWallet$ github.com/nghuyenthevinh2000/bitcoin-playground
// create bob wallet and fund bob wallet with 1000 sats sent from btcd registered mining wallet
func TestBtcdCreateWallet(t *testing.T) {
	suite := TestSuite{}
	suite.setupSuite(t)

	// use a HD wallet seed
	seedStr := strings.TrimSpace(strings.ToLower(BOB_WALLET_SEED))
	seed, err := hex.DecodeString(seedStr)
	assert.Nil(t, err)
	pubPass := []byte("public")
	privPass := []byte("private")

	// setup wallet loader
	db, err := walletdb.Create("bdb", "boltdb/bob.db", true, 60*time.Second)
	assert.Nil(t, err)

	loader, err := wallet.NewLoaderWithDB(
		suite.btcdChainConfig, 250, db,
		// TODO: need further investigation into this from wallet/example_test.go
		func() (bool, error) {
			return false, nil
		},
	)
	assert.Nil(t, err)

	// retrieve wallet
	w, err := loader.CreateNewWallet(pubPass, privPass, seed, time.Now())
	t.Logf("err: %v", err)
	if err != nil {
		w, err = loader.OpenExistingWallet(pubPass, false)
		assert.Nil(t, err)
	}
	w.SynchronizeRPC(suite.walletChainClient)

	time.Sleep(5 * time.Second)

	bals, err := w.AccountBalances(waddrmgr.KeyScopeBIP0044, 1)
	assert.Nil(t, err)
	assert.Equal(t, bals[0].AccountBalance, btcutil.Amount(3000000))
	t.Logf("balances: %+v", bals)
}

// go test -v -run ^TestBallGameContract$ github.com/nghuyenthevinh2000/bitcoin-playground
func TestBallGameContract(t *testing.T) {
	suite := TestSuite{}
	suite.setupSuite(t)

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

	// result hash of the game between VN and TL
	vn := sha256.Sum256([]byte("VN wins"))
	tl := sha256.Sum256([]byte("TL wins"))

	// fetch an alice witness address
	aliceW, err := alice.CurrentAddress(0, waddrmgr.KeyScopeBIP0084)
	assert.Nil(t, err)
	bobW, err := bob.CurrentAddress(0, waddrmgr.KeyScopeBIP0084)
	assert.Nil(t, err)

	logBals := func(alice, bob *wallet.Wallet) {
		bals, _ := alice.CalculateBalance(1)
		t.Logf("Alice's balances: %+v", bals)

		bals, _ = bob.CalculateBalance(1)
		t.Logf("Bob's balances: %+v", bals)
	}

	logBals(alice, bob)

	ballGameScript := func(aliceW, bobW btcutil.Address) []byte {
		// Alice bets that VN wins
		// Bob bets that TL wins
		builder := txscript.NewScriptBuilder()
		builder.AddOp(txscript.OP_IF)
		builder.AddOp(txscript.OP_SHA256).AddData(vn[:]).AddOp(txscript.OP_EQUALVERIFY)
		builder.AddData(aliceW.ScriptAddress()).AddOp(txscript.OP_CHECKSIG)
		builder.AddOp(txscript.OP_ELSE)
		builder.AddOp(txscript.OP_SHA256).AddData(tl[:]).AddOp(txscript.OP_EQUALVERIFY)
		builder.AddData(bobW.ScriptAddress()).AddOp(txscript.OP_CHECKSIG)
		builder.AddOp(txscript.OP_ENDIF)
		pkScript, err := builder.Script()
		assert.Nil(t, err)
		return pkScript
	}

	ballGame := func(aliceW, bobW btcutil.Address) (*btcutil.AddressWitnessScriptHash, []byte) {
		pkgScript := ballGameScript(aliceW, bobW)
		witnessScriptCommitment := sha256.Sum256(pkgScript)
		p2wsh, err := btcutil.NewAddressWitnessScriptHash(witnessScriptCommitment[:], suite.btcdChainConfig)
		assert.Nil(t, err)
		return p2wsh, pkgScript
	}

	// create a ballgame address
	p2wsh, pkScript := ballGame(aliceW, bobW)
	t.Log("p2wsh: ", p2wsh.EncodeAddress())
	t.Log("pkScript: ", hex.EncodeToString(pkScript))

	rewardAmount := btcutil.Amount(10000000)
	commitHash, err := suite.walletClient.SendToAddress(p2wsh, rewardAmount)
	assert.Nil(t, err)

	// generate a block to confirm the transaction
	suite.generateBlocks(1)

	// log the transaction: txid, index, input, output
	rawTx, err := suite.walletClient.GetRawTransaction(commitHash)
	assert.Nil(t, err)

	t.Log("txid: ", rawTx)

	logBals(alice, bob)
	withdrawFromBallgameAddress := func(w *wallet.Wallet, winHash [32]byte) {

		tx := wire.NewMsgTx(2)
		tx.AddTxIn(&wire.TxIn{
			PreviousOutPoint: *wire.NewOutPoint(commitHash, 0),
			Witness:          [][]byte{pkScript},
		})

		fee := btcutil.Amount(1000)
		output := btcutil.Amount(10000000 - fee)

		// check a winner
		tx.AddTxOut(&wire.TxOut{
			PkScript: aliceW.ScriptAddress(),
			Value:    int64(output),
		})

		sigHashes := txscript.NewTxSigHashes(tx, txscript.NewCannedPrevOutputFetcher(pkScript, int64(output)))

		// Sign the transaction
		privKey := extractPrivateKey(w, t)
		sigScript, err := txscript.WitnessSignature(tx, sigHashes, 0, int64(output), pkScript, txscript.SigHashAll, privKey, true)
		assert.Nil(t, err)

		fmt.Println("sigScript: ", (sigScript))

		tx.TxIn[0].Witness = append(tx.TxIn[0].Witness, sigScript[0])
		tx.TxIn[0].Witness = append(tx.TxIn[0].Witness, privKey.PubKey().SerializeCompressed())
		tx.TxIn[0].Witness = append(tx.TxIn[0].Witness, winHash[:])

		fmt.Println("witness: ", tx.TxIn[0].Witness)

		// Broadcast the transaction
		txHash, err := suite.walletClient.SendRawTransaction(tx, false)
		assert.Nil(t, err)
		t.Logf("txHash: %s", txHash)

		// generate a block to confirm the transaction
		suite.generateBlocks(1)

		logBals(alice, bob)
	}

	// Simulate both outcomes and log the results
	t.Logf("=== Simulating Alice wins ===")
	withdrawFromBallgameAddress(alice, vn)

	// t.Logf("=== Simulating Bob wins ===")
	// withdrawFromBallgameAddress(bob, tl)
}

func extractPrivateKey(w *wallet.Wallet, t *testing.T) *btcec.PrivateKey {
	// Create a channel with a sufficiently long timeout
	timeout := make(chan time.Time, 1)
	go func() {
		time.Sleep(10 * time.Minute)
		timeout <- time.Now()
	}()

	// Unlock the wallet using the private passphrase and timeout channel
	err := w.Unlock([]byte("private"), timeout)
	assert.Nil(t, err)

	// Fetch the current address to get the corresponding private key
	addr, err := w.CurrentAddress(0, waddrmgr.KeyScopeBIP0084)
	assert.Nil(t, err)

	// Dump the WIF format private key of the address
	privKeyWIF, err := w.DumpWIFPrivateKey(addr)
	assert.Nil(t, err)

	// Decode the WIF format private key
	wif, err := btcutil.DecodeWIF(privKeyWIF)
	assert.Nil(t, err)

	// Return the extracted private key
	privKey := wif.PrivKey
	return privKey
}

func (s *TestSuite) setupSuite(t *testing.T) {
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

func (s *TestSuite) openWallet(t *testing.T, seed, wallet_name string) *wallet.Wallet {
	seedStr := strings.TrimSpace(strings.ToLower(seed))
	seedBytes, err := hex.DecodeString(seedStr)
	assert.Nil(t, err)
	pubPass := []byte("public")
	privPass := []byte("private")

	// setup wallet loader
	db, err := walletdb.Create("bdb", fmt.Sprintf("boltdb/%s.db", wallet_name), true, 60*time.Second)
	assert.Nil(t, err)

	loader, err := wallet.NewLoaderWithDB(
		s.btcdChainConfig, 250, db,
		// TODO: need further investigation into this from wallet/example_test.go
		func() (bool, error) {
			return false, nil
		},
	)
	assert.Nil(t, err)

	// retrieve wallet
	w, err := loader.CreateNewWallet(pubPass, privPass, seedBytes, time.Now())
	if err != nil {
		w, err = loader.OpenExistingWallet(pubPass, false)
		assert.Nil(t, err)
	}
	w.SynchronizeRPC(s.walletChainClient)

	time.Sleep(3 * time.Second)

	t.Logf("wallet %s opened", wallet_name)
	return w
}

// this is for deriving witness pubkey hash from public key
func (s *TestSuite) deriveWitnessPubkeyHash(wif *btcutil.WIF) string {
	pubKey := wif.SerializePubKey()
	pubKeyHash := btcutil.Hash160(pubKey)
	witness, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, s.btcdChainConfig)
	assert.Nil(s.t, err)
	return witness.EncodeAddress()
}

// fund wallet with 0.1 BTC from mining wallet
func (s *TestSuite) fundWallet(wallet *wallet.Wallet, amount btcutil.Amount) {
	addr, err := wallet.CurrentAddress(0, waddrmgr.KeyScopeBIP0044)
	assert.Nil(s.t, err)

	s.t.Logf("address: %s", addr.EncodeAddress())

	// send 0.1 BTC to the address
	_, err = s.walletClient.SendToAddress(addr, amount)
	assert.Nil(s.t, err)

	// generate a block to confirm the transaction
	s.generateBlocks(1)
}

func (s *TestSuite) generateBlocks(num int) {
	num_string := strconv.Itoa(num)
	fmt.Println("Run cmd: ", "btcctl", "--simnet", "--notls", "-u", MockBtcUser, "-P", MockBtcPass, "generate", num_string)
	err := exec.Command("btcctl", "--simnet", "--notls", "-u", MockBtcUser, "-P", MockBtcPass, "generate", num_string).Run()
	assert.Nil(s.t, err)
	time.Sleep(3 * time.Second)
}

func (s *TestSuite) generateSeed() []byte {
	seed, err := hdkeychain.GenerateSeed(hdkeychain.RecommendedSeedLen)
	assert.Nil(s.t, err)
	return seed
}

func (s *TestSuite) generateSeedString() string {
	seed := s.generateSeed()
	return hex.EncodeToString(seed)
}
