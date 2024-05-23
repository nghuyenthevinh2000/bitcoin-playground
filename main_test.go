package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/btcsuite/btcwallet/walletdb"
	_ "github.com/btcsuite/btcwallet/walletdb/bdb"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
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
	ALICE_WALLET_SEED   = "3639d13ae312fec5431aab8861937e5bdce1105df13bda7311aef60a0d91aea2"
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

	// Alice, Bob private key
	wallets := suite.generateWallets(t, 2)
	alice := wallets[0]
	bob := wallets[1]

	t.Logf("alice: %s", alice.String())

	wif, err := btcutil.DecodeWIF(alice.String())
	assert.Nil(t, err)

	t.Logf("wif: %s", wif.String())

	// fund the addresss
	// suite.fundWallets(t, wallets, cfg)

	os.Exit(0)

	// result hash of the game between VN and TL
	vn := sha256.Sum256([]byte("VN wins"))
	tl := sha256.Sum256([]byte("TL wins"))

	// Alice bets that VN wins
	// Bob bets that TL wins
	builder := txscript.NewScriptBuilder()
	builder.AddOp(txscript.OP_IF)
	builder.AddOp(txscript.OP_SHA256).AddData(vn[:]).AddOp(txscript.OP_EQUALVERIFY)
	builder.AddData(alice.SerializePubKey()).AddOp(txscript.OP_CHECKSIG)
	builder.AddOp(txscript.OP_ELSE)
	builder.AddOp(txscript.OP_SHA256).AddData(tl[:]).AddOp(txscript.OP_EQUALVERIFY)
	builder.AddData(bob.SerializePubKey()).AddOp(txscript.OP_CHECKSIG)
	builder.AddOp(txscript.OP_ENDIF)
	pkScript, err := builder.Script()
	assert.Nil(t, err)

	// create a P2WSH address
	witnessScriptCommitment := sha256.Sum256(pkScript)
	address, err := btcutil.NewAddressWitnessScriptHash(witnessScriptCommitment[:], &chaincfg.RegressionNetParams)
	assert.Nil(t, err)
	t.Logf("P2SH address: %s", address.EncodeAddress())
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

func (s *TestSuite) generateWallets(t *testing.T, num int) []*btcutil.WIF {
	wallets := make([]*btcutil.WIF, num)
	for i := 0; i < num; i++ {
		privKey, err := secp256k1.GeneratePrivateKey()
		assert.Nil(t, err)
		// WIF: Wallet Import Format
		wif, err := btcutil.NewWIF(privKey, s.btcdChainConfig, true)
		assert.Nil(t, err)
		wallets[i] = wif
		wif.String()
	}

	return wallets
}

// this is for deriving witness pubkey hash from public key
func (s *TestSuite) deriveWitnessPubkeyHash(wif *btcutil.WIF) string {
	pubKey := wif.SerializePubKey()
	pubKeyHash := btcutil.Hash160(pubKey)
	witness, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, s.btcdChainConfig)
	assert.Nil(s.t, err)
	return witness.EncodeAddress()
}

// fund wallet with 1 BTC from main wallet in regtest
func (s *TestSuite) fundWallets(wallets []*btcutil.WIF) {
	for _, wallet := range wallets {
		// generate 101 blocks to finalize coinbase rewards
		// addr := s.deriveWitnessPubkeyHash(t, wallet, cfg)
		// err := exec.Command("bitcoin-cli", "-regtest", "-rpcport=18443", "-rpcuser=regtest", "-rpcpassword=regtest", "sendtoaddress", addr, "1").Run()
		// assert.Nil(t, err)

		// check for balance
		err := s.chainClient.ImportPrivKey(wallet)
		assert.Nil(s.t, err)
		// err = exec.Command("bitcoin-cli", "-regtest", "-rpcport=18443", "-rpcuser=regtest", "-rpcpassword=regtest", "-generate", "100").Run()
		// assert.Nil(t, err)
		amt, err := s.chainClient.GetBalance("alice")
		assert.Nil(s.t, err)
		s.t.Logf("balance of %s: %f", "alice", amt.ToBTC())
	}
}

func (s *TestSuite) generateBlocks(num int) {
	num_string := string(rune(num))
	err := exec.Command("btcctl", "--simnet", "--notls", "-rpcuser", MockBtcUser, "-rpcpass", MockBtcPass, "generate", num_string).Run()
	assert.Nil(s.t, err)
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

// construct inputs and outputs to send a BTC amount to an address
func (s *TestSuite) sendToAddress(addr btcutil.Address, amount btcutil.Amount) {
	// Get unspent transaction outputs (UTXOs) for the from address
	// utxos, err := s.walletClient.ListUnspent()
	// assert.Nil(s.t, err)
}
