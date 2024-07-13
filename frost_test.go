package main

import (
	"crypto/sha256"
	"fmt"
	"testing"

	btcec "github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/stretchr/testify/assert"
)

type FrostParticipant struct {
	// Pederson participant
	*PedersonParticipant

	// schnorr
	adaptor_sig *schnorr.Signature
}

// this is a minimal FROST implementation for educational purposes
// an overview os its Schnorr signature:
// our setting has n = 7 participants, with threshold t = 5 participants
// go test -v -run ^TestFrost$ github.com/nghuyenthevinh2000/bitcoin-playground
func TestFrost(t *testing.T) {
	suite := TestSuite{}
	suite.setupStaticSimNetSuite(t)

	n := 7
	thres := 5

	// 1.1: each participant generates their Pederson secret shares, and secret commitments
	participants := make([]*FrostParticipant, n)
	for i := 0; i < n; i++ {
		fmt.Println("Creating participant", i)
		participants[i] = suite.newFrostParticipantDKG(thres, n)
	}

	// 1.2: each participants exchange their shares with all others

}

func (s *TestSuite) newFrostParticipantDKG(thres, n int) *FrostParticipant {
	participant := &FrostParticipant{}
	participant.PedersonParticipant = s.newPedersonParticipantDKG(thres, n)

	// calculating this participant adaptor sig
	nonce := s.generate32BSeed()
	r := new(btcec.ModNScalar)
	r.SetBytes(&nonce)
	R := new(btcec.JacobianPoint)
	btcec.ScalarBaseMultNonConst(r, R)
	R.ToAffine()
	if R.Y.IsOdd() {
		r.Negate()
	}

	// calculating commitment hash
	// c = H(stamp, P_i, R)
	secret := participant.PedersonParticipant.testPolynomial[0]
	pub_point := new(btcec.JacobianPoint)
	btcec.ScalarBaseMultNonConst(secret, pub_point)
	pub_point.ToAffine()
	if pub_point.Y.IsOdd() {
		secret.Negate()
	}
	pub_key := btcec.NewPublicKey(&pub_point.X, &pub_point.Y)

	message_hash := sha256.Sum256([]byte("a random message"))
	commitment_data := make([]byte, 0)
	commitment_data = append(commitment_data, schnorr.SerializePubKey(pub_key)...)
	commitment_data = append(commitment_data, R.X.Bytes()[:]...)
	commitment_data = append(commitment_data, message_hash[:]...)

	commitment_hash := chainhash.TaggedHash([]byte("FROST_TAG"), commitment_data)
	c := new(btcec.ModNScalar)
	c.SetByteSlice(commitment_hash[:])

	s_scalar := new(btcec.ModNScalar).Mul2(secret, c).Add(r)
	sig := schnorr.NewSignature(&R.X, s_scalar)

	verified := sig.Verify(message_hash[:], pub_key)
	assert.True(s.t, verified, "Frost participant adaptor sig verification failed")

	participant.adaptor_sig = sig
	return participant
}
