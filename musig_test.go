package main

import (
	"crypto/sha256"
	"testing"

	btcec "github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
	"github.com/stretchr/testify/assert"
)

// go test -v -run ^TestMuSig2$ github.com/nghuyenthevinh2000/bitcoin-playground
func TestMuSig2(t *testing.T) {
	s := TestSuite{}
	s.setupSuite(t)

	// msg
	msgBytes := sha256.Sum256([]byte("VN Bitcoin Builders"))

	// create aggregated public key
	_, pub_1, priv_1 := s.generateKeyPair()
	_, pub_2, priv_2 := s.generateKeyPair()
	_, pub_3, priv_3 := s.generateKeyPair()
	pubKeys := []*btcec.PublicKey{pub_1, pub_2, pub_3}
	aggrPubKey, _, _, err := musig2.AggregateKeys(pubKeys, false)
	assert.Nil(s.t, err)

	// create aggregated nonces
	nonce_1, err := musig2.GenNonces(musig2.WithPublicKey(pub_1))
	assert.Nil(s.t, err)
	nonce_2, err := musig2.GenNonces(musig2.WithPublicKey(pub_2))
	assert.Nil(s.t, err)
	nonce_3, err := musig2.GenNonces(musig2.WithPublicKey(pub_3))
	assert.Nil(s.t, err)
	aggrNonces, err := musig2.AggregateNonces([][66]byte{nonce_1.PubNonce, nonce_2.PubNonce, nonce_3.PubNonce})
	assert.Nil(s.t, err)

	// generate partial signatures for each participant
	// sign already negates nonce with odd y - value
	// s1, R
	ps_1, err := musig2.Sign(nonce_1.SecNonce, priv_1, aggrNonces, pubKeys, msgBytes)
	assert.Nil(s.t, err)
	// s2, R
	ps_2, err := musig2.Sign(nonce_2.SecNonce, priv_2, aggrNonces, pubKeys, msgBytes)
	assert.Nil(s.t, err)
	// s3, R
	ps_3, err := musig2.Sign(nonce_3.SecNonce, priv_3, aggrNonces, pubKeys, msgBytes)
	assert.Nil(s.t, err)

	// aggregate partial signatures
	// the combined nonce is in each partial signature R value
	schnorrSig := musig2.CombineSigs(ps_2.R, []*musig2.PartialSignature{ps_1, ps_2, ps_3})

	// verify aggregated signature
	// check aggregated R value, it should be the same as when signing
	correct := schnorrSig.Verify(msgBytes[:], aggrPubKey.FinalKey)
	assert.True(s.t, correct)
}
