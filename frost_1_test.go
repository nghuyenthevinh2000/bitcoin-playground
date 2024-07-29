package main

import (
	"testing"

	"github.com/nghuyenthevinh2000/bitcoin-playground/testhelper"
)

// go test -v -run ^TestFrostSignature1$ github.com/nghuyenthevinh2000/bitcoin-playground
// TODO: handle sign problem, flaky issue
func TestFrostSignature1(t *testing.T) {
	suite := testhelper.TestSuite{}
	suite.SetupStaticSimNetSuite(t)
	defer suite.StaticSimNetTearDown()

	// frost
	n := int64(7)
	threshold := int64(5)
	participants := make([]*testhelper.FrostParticipant, n)
	for i := int64(0); i < n; i++ {
		participants[i] = testhelper.NewFrostParticipant(&suite, n, threshold, i+1, nil)
	}

	// generate challenges
	for i := int64(0); i < n; i++ {
		participant := participants[i]
		challenge := participant.CalculateSecretProofs([32]byte{})
		participant.VerifySecretProofs([32]byte{}, challenge, i+1, participant.PolynomialCommitments[0])
	}

	// calculate secret shares
	for i := int64(0); i < n; i++ {
		participant := participants[i]
		participant.CalculateSecretShares()
		for j := int64(0); j < n; j++ {
			secret := participant.GetSecretShares(j + 1)
			participant.VerifyPublicSecretShares(secret, participant.PolynomialCommitments, uint32(j+1))
		}
	}
}
