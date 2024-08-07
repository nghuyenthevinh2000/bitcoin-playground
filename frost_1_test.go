package main

import (
	"log"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/nghuyenthevinh2000/bitcoin-playground/testhelper"
)

// go test -v -run ^TestFrostSignature1$ github.com/nghuyenthevinh2000/bitcoin-playground
// TODO: handle sign problem, flaky issue
func TestFrostSignature1(t *testing.T) {
	suite := testhelper.TestSuite{}
	suite.SetupStaticSimNetSuite(t)

	// frost
	n := int64(7)
	threshold := int64(5)
	participants := make([]*testhelper.FrostParticipant, n)
	logger := log.Default()
	for i := int64(0); i < n; i++ {
		participants[i] = testhelper.NewFrostParticipant(&suite, logger, n, threshold, i+1, nil)
	}

	// update polynomial commitments
	for i := int64(0); i < n; i++ {
		for j := int64(0); j < n; j++ {
			if i == j {
				continue
			}
			participant := participants[j]
			participant.UpdatePolynomialCommitments(i+1, participants[i].PolynomialCommitments[i+1])
		}
	}

	// generate challenges
	for i := int64(0); i < n; i++ {
		participant := participants[i]
		challenge := participant.CalculateSecretProofs([32]byte{})
		participant.VerifySecretProofs([32]byte{}, challenge, i+1, participant.PolynomialCommitments[participant.Position][0])
	}

	// calculate secret shares
	secret_shares_map := make(map[int64]map[int64]*btcec.ModNScalar)
	for i := int64(0); i < n; i++ {
		secret_shares_map[i+1] = make(map[int64]*btcec.ModNScalar)
	}
	for i := int64(0); i < n; i++ {
		participant := participants[i]
		participant.CalculateSecretShares()

		// distribute to all participants
		for j := int64(0); j < n; j++ {
			secret := participant.GetSecretShares(j + 1)
			secret_shares_map[j+1][i+1] = secret
		}
	}

	for i := int64(0); i < n; i++ {
		participant := participants[i]
		participant.CalculateSecretShares()
		for j := int64(0); j < n; j++ {
			secret := secret_shares_map[participant.Position][j+1]
			participant.VerifyPublicSecretShares(secret, j+1, uint32(participant.Position))
		}

		// try out batch verification of secret shares
		participant.VerifyBatchPublicSecretShares(secret_shares_map[participant.Position], uint32(participant.Position))
	}
}
