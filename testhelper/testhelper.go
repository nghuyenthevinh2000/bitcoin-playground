package testhelper

import (
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/blockchain"
	btcec "github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	_ "github.com/btcsuite/btcd/database/ffldb"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/stretchr/testify/assert"
)

type TestSuite struct {
	T *testing.T

	// this is for bitcoin live network
	ChainClient       *rpcclient.Client
	WalletClient      *rpcclient.Client
	WalletChainClient *chain.RPCClient
	BtcdConnConfig    *rpcclient.ConnConfig
	BtcdChainConfig   *chaincfg.Params

	// this is for bitcoin synthetic test
	UtxoViewpoint *blockchain.UtxoViewpoint
	SigCache      *txscript.SigCache
	HashCache     *txscript.HashCache
}

func (s *TestSuite) SetupRegNetSuite(t *testing.T) {
	s.T = t
	s.BtcdChainConfig = &chaincfg.RegressionNetParams
}

func (s *TestSuite) SetupStaticSimNetSuite(t *testing.T) {
	s.T = t
	s.BtcdChainConfig = &chaincfg.SimNetParams

	// setup new utxo viewpoint
	s.UtxoViewpoint = blockchain.NewUtxoViewpoint()
	s.SigCache = txscript.NewSigCache(50000)
	s.HashCache = txscript.NewHashCache(50000)
}

func (s *TestSuite) SetupSimNetSuite(t *testing.T) {
	var err error

	s.T = t
	// connect to bitcoin btcd simnet network
	s.BtcdConnConfig = &rpcclient.ConnConfig{
		Host:         MockBtcdHost,
		Endpoint:     "ws",
		User:         MockBtcUser,
		Pass:         MockBtcPass,
		HTTPPostMode: false,
		DisableTLS:   true,
	}
	s.BtcdChainConfig = &chaincfg.SimNetParams
	s.BtcdChainConfig.DefaultPort = MockBtcdHost
	// todo: determine what to do with bitcoin events for notification handlers
	s.ChainClient, err = rpcclient.New(s.BtcdConnConfig, nil)
	assert.Nil(t, err)

	// connect to bitcoin wallet simnet network
	s.WalletChainClient, err = chain.NewRPCClientWithConfig(&chain.RPCClientConfig{
		Conn:  s.BtcdConnConfig,
		Chain: s.BtcdChainConfig,
	})
	assert.Nil(t, err)
	// start socket connection
	err = s.WalletChainClient.Start()
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
	s.WalletClient, err = rpcclient.New(walletConnConfig, nil)
	assert.Nil(t, err)

	// open wallet for 10 mins
	err = s.WalletClient.WalletPassphrase(MockWalletPass, 10*60)
	assert.Nil(t, err)
}

func (s *TestSuite) BytesToHexStr(b []byte) string {
	return hex.EncodeToString(b)
}

func (s *TestSuite) GenerateBlocks(num uint32) {
	_, err := s.ChainClient.Generate(num)
	assert.Nil(s.T, err)
}

func (s *TestSuite) GenerateSeed() []byte {
	seed, err := hdkeychain.GenerateSeed(hdkeychain.RecommendedSeedLen)
	assert.Nil(s.T, err)
	return seed
}

func (s *TestSuite) Generate32BSeed() [hdkeychain.RecommendedSeedLen]byte {
	var res [hdkeychain.RecommendedSeedLen]byte
	seed, err := hdkeychain.GenerateSeed(hdkeychain.RecommendedSeedLen)
	assert.Nil(s.T, err)
	copy(res[:], seed)
	return res
}

func (s *TestSuite) GenerateSeedString() string {
	seed := s.GenerateSeed()
	return hex.EncodeToString(seed[:])
}

type KeyPair struct {
	Pub  *btcec.PublicKey
	priv *btcec.PrivateKey
}

func (key *KeyPair) GetTestPriv() *btcec.PrivateKey {
	return key.priv
}

// empty seed string will generate new keypair
func (s *TestSuite) NewHDKeyPairFromSeed(seed string) ([]byte, KeyPair) {
	var seedBytes []byte

	if seed == "" {
		seedBytes = s.GenerateSeed()
	} else {
		var err error
		seedBytes, err = hex.DecodeString(seed)
		assert.Nil(s.T, err)
	}

	hd, err := hdkeychain.NewMaster(seedBytes, s.BtcdChainConfig)
	assert.Nil(s.T, err)
	pub, err := hd.ECPubKey()
	assert.Nil(s.T, err)
	priv, err := hd.ECPrivKey()
	assert.Nil(s.T, err)

	return seedBytes, KeyPair{pub, priv}
}

// empty bytes will generate new keypair
func (s *TestSuite) NewKeyPairFromBytes(bytes []byte) KeyPair {
	var keyBytes []byte

	if bytes == nil {
		keyBytes = s.GenerateSeed()
	} else {
		keyBytes = bytes
	}

	priv, pub := btcec.PrivKeyFromBytes(keyBytes)
	return KeyPair{pub, priv}
}

// this is for deriving witness pubkey hash from public key
func (s *TestSuite) DeriveWitnessPubkeyHash(wif *btcutil.WIF) string {
	pubKey := wif.SerializePubKey()
	pubKeyHash := btcutil.Hash160(pubKey)
	witness, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, s.BtcdChainConfig)
	assert.Nil(s.T, err)
	return witness.EncodeAddress()
}

func (s *TestSuite) ConvertPubKeyToTrAddress(pub *btcec.PublicKey) string {
	pub_schnorr := schnorr.SerializePubKey(pub)
	address, err := btcutil.NewAddressTaproot(pub_schnorr, s.BtcdChainConfig)
	assert.Nil(s.T, err)
	return address.EncodeAddress()
}

func (s *TestSuite) ConvertPrivKeyToWIF(priv *btcec.PrivateKey) string {
	wif, err := btcutil.NewWIF(priv, s.BtcdChainConfig, true)
	assert.Nil(s.T, err)

	return wif.String()
}
