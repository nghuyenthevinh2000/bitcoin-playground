package main

import (
	"crypto/sha256"
	"os"
	"testing"
	"time"

	"github.com/nghuyenthevinh2000/bitcoin-playground/testhelper"
	"github.com/stretchr/testify/assert"

	btcec "github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	_ "github.com/btcsuite/btcwallet/walletdb/bdb"
)

var (
	reg testhelper.RegBitcoinProcess
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
	s := testhelper.TestSuite{}
	s.SetupSimNetSuite(t)

	// block 10
	hash, err := s.ChainClient.GetBlockHash(10)
	assert.Nil(t, err)
	block_10, err := s.ChainClient.GetBlock(hash)
	assert.Nil(t, err)

	// block 11
	hash, err = s.ChainClient.GetBlockHash(11)
	assert.Nil(t, err)
	block_11, err := s.ChainClient.GetBlock(hash)
	assert.Nil(t, err)

	assert.Equal(t, block_10.Header.BlockHash(), block_11.Header.PrevBlock)
}

// go test -v -run ^TestSeedString$ github.com/nghuyenthevinh2000/bitcoin-playground
func TestSeedString(t *testing.T) {
	suite := testhelper.TestSuite{}
	suite.SetupStaticSimNetSuite(t)
	defer suite.StaticSimNetTearDown()

	for i := 0; i < 3; i++ {
		seed := suite.GenerateSeedString()
		t.Logf("seed: %s", seed)
	}
}

// go test -v -run ^TestSchnorr$ github.com/nghuyenthevinh2000/bitcoin-playground
func TestSchnorr(t *testing.T) {
	s := testhelper.TestSuite{}
	s.SetupStaticSimNetSuite(t)
	defer s.StaticSimNetTearDown()

	// s = t + e * d
	_, t_pair := s.NewHDKeyPairFromSeed("")
	t_priv := t_pair.GetTestPriv().Key
	R := new(btcec.JacobianPoint)
	t_pair.Pub.AsJacobian(R)
	// Y - coordinate has to be even to determine exact point
	if R.Y.IsOdd() {
		R.Y.Negate(1)
		t_priv.Negate()
	}
	_, d_pair := s.NewHDKeyPairFromSeed("")
	d := d_pair.GetTestPriv().Key
	// Jacobian coordinates (X, Y, Z)
	P := new(btcec.JacobianPoint)
	d_pair.Pub.AsJacobian(P)
	// Affine coordinates (X, Y)
	// Y - coordinate has to be even to determine exact point
	P.ToAffine()
	if P.Y.IsOdd() {
		P.Y.Negate(1)
		d.Negate()
	}
	// e = H("BIP0340/challenge" || R || P || m)
	m := []byte("123")
	hash_m := sha256.Sum256(m)

	e := chainhash.TaggedHash(chainhash.TagBIP0340Challenge, t_pair.Pub.SerializeCompressed()[1:], d_pair.Pub.SerializeCompressed()[1:], hash_m[:])
	var e_scalar btcec.ModNScalar
	e_scalar.SetByteSlice(e[:])
	S := new(btcec.ModNScalar).Mul2(&e_scalar, &d).Add(&t_priv)
	sig := schnorr.NewSignature(&R.X, S)

	ok := sig.Verify(hash_m[:], d_pair.Pub)
	assert.True(t, ok)
}

// go test -v -run ^TestJacobianOdd$ github.com/nghuyenthevinh2000/bitcoin-playground
func TestJacobianOdd(t *testing.T) {
	s := testhelper.TestSuite{}
	s.SetupStaticSimNetSuite(t)
	defer s.StaticSimNetTearDown()

	d_seed := s.Generate32BSeed()
	e_seed := s.Generate32BSeed()
	d := new(btcec.ModNScalar)
	d.SetBytes(&d_seed)
	D := new(btcec.JacobianPoint)
	btcec.ScalarBaseMultNonConst(d, D)
	e := new(btcec.ModNScalar)
	e.SetBytes(&e_seed)
	E := new(btcec.JacobianPoint)
	btcec.ScalarBaseMultNonConst(e, E)

	p_seed := s.Generate32BSeed()
	p_R_seed := make([]byte, len(p_seed))
	copy(p_R_seed, p_seed[:])
	p := new(btcec.ModNScalar)
	p.SetBytes(&p_seed)

	// R = D*E^p
	p_R := new(btcec.ModNScalar)
	p_R.SetByteSlice(p_R_seed)
	term1 := new(btcec.JacobianPoint)
	btcec.ScalarMultNonConst(p_R, E, term1)
	R := new(btcec.JacobianPoint)
	btcec.AddNonConst(D, term1, R)
	if R.Y.IsOdd() {
		R.Y.Negate(1)
		R.Y.Normalize()
	}

	// R1 = g^(d + e*p)
	R1 := new(btcec.JacobianPoint)
	term2 := new(btcec.ModNScalar)
	term2.Mul2(e, p)
	de := new(btcec.ModNScalar).Add2(d, term2)
	btcec.ScalarBaseMultNonConst(de, R1)
	if R1.Y.IsOdd() {
		d.Negate()
		e.Negate()
	}
	term2 = new(btcec.ModNScalar)
	term2.Mul2(e, p)
	de = new(btcec.ModNScalar).Add2(d, term2)
	btcec.ScalarBaseMultNonConst(de, R1)

	t.Logf("p: %v, p_R: %v\n", p, p_R)

	R.ToAffine()
	R1.ToAffine()
	assert.Equal(t, R, R1)
}
