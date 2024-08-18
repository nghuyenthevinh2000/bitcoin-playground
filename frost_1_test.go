package main

import (
	"log"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/nghuyenthevinh2000/bitcoin-playground/testhelper"
	"github.com/stretchr/testify/assert"
)

func TestFrostSignature1(t *testing.T) {
	suite := testhelper.TestSuite{}
	suite.SetupStaticSimNetSuite(t)

	// frost
	n := 1000
	threshold := 667
	participants := make([]*testhelper.FrostParticipant, n)
	logger := log.Default()
	logger.Println("Starting")
	timeNow := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			participants[i] = testhelper.NewFrostParticipant(&suite, logger, n, threshold, i+1, nil)
		}(i)
	}
	// Wait for all goroutines to complete
	wg.Wait()
	logger.Printf("Generating participants takes: %v\n", time.Since(timeNow))

	timeNow = time.Now()
	// update polynomial commitments
	polynomialCommitments := make([][]*btcec.PublicKey, len(participants)+1)
	for i := 0; i < len(participants); i++ {
		polynomialCommitments[i+1] = participants[i].PolynomialCommitment
		participants[i].PolynomialCommitments = polynomialCommitments
	}
	logger.Printf("UpdatePolynomialCommitments takes: %v\n", time.Since(timeNow))

	// generate challenges
	timeNow = time.Now()
	for i := 0; i < len(participants); i++ {
		participant := participants[i]
		challenge := participant.CalculateSecretProofs([32]byte{})
		participant.VerifySecretProofs([32]byte{}, challenge, i+1, participant.PolynomialCommitments[participant.Position][0])
	}
	logger.Printf("VerifySecretProofs takes: %v\n", time.Since(timeNow))

	// calculate secret shares

	timeNow = time.Now()
	secretSharesMap := make([]map[int]*btcec.ModNScalar, len(participants)+1)
	for i := 0; i < len(participants); i++ {
		secretSharesMap[i+1] = make(map[int]*btcec.ModNScalar)
	}

	for i := 0; i < len(participants); i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			participants[i].CalculateSecretShares()
		}(i)
	}
	wg.Wait()
	logger.Printf("CalculateSecretShares takes: %v\n", time.Since(timeNow))

	timeNow = time.Now()
	for i := 0; i < len(participants); i++ {
		for j := 0; j < len(participants); j++ {
			secret := participants[i].GetSecretShares(j + 1)
			secretSharesMap[j+1][i+1] = secret
		}
	}
	logger.Printf("GetSecretShares takes: %v\n", time.Since(timeNow))

	//timeNow = time.Now()
	//for i := 0; i < len(participants); i++ {
	//	participant := participants[i]
	//	timeNow1 := time.Now()
	//	for j := 0; j < len(participants); j++ {
	//		wg.Add(1)
	//		go func(j int) {
	//			defer wg.Done()
	//			secret := secretSharesMap[participant.Position][j+1]
	//			participant.VerifyPublicSecretShares(secret, j+1)
	//		}(j)
	//	}
	//	wg.Wait()
	//	logger.Printf("VerifyPublicSecretShares takes: %v\n", time.Since(timeNow1))
	//}
	//logger.Printf("Total VerifyPublicSecretShares takes: %v\n", time.Since(timeNow))

	timeNow = time.Now()
	for i := 0; i < 1; i++ {
		wg.Add(1)
		participant := participants[i]
		go func() {
			defer wg.Done()
			participant.VerifyBatchPublicSecretShares(secretSharesMap[participant.Position])
		}()
	}
	wg.Wait()
	logger.Printf("VerifyBatchPublicSecretShares takes: %v\n", time.Since(timeNow))

	// calculate public signing shares
	timeNow = time.Now()
	signingSharesMap := make(map[int]*btcec.ModNScalar)
	for i := 0; i < n; i++ {
		participant := participants[i]
		signingShares := new(btcec.ModNScalar)
		for j := 0; j < n; j++ {
			secret := secretSharesMap[participant.Position][j+1]
			signingShares.Add(secret)
		}
		signingSharesMap[participant.Position] = signingShares
	}
	logger.Printf("signingSharesMap takes: %v\n", time.Since(timeNow))

	// calculate public signing shares
	timeNow = time.Now()
	for i := 0; i < len(participants); i++ {
		participant := participants[i]
		wg.Add(1)
		go func() {
			defer wg.Done()
			participant.CalculateInternalPublicSigningShares(signingSharesMap[participant.Position])
		}()
	}
	wg.Wait()
	logger.Printf("CalculateInternalPublicSigningShares takes: %v\n", time.Since(timeNow))

	timeNow = time.Now()
	aggregateCommitments := make([]*btcec.JacobianPoint, threshold+1)
	for j := 0; j <= threshold; j++ {
		wg.Add(1)
		agg := new(btcec.JacobianPoint)
		go func(j int) {
			defer wg.Done()
			// parallel computation
			// \prod_{j=0}^{t} A_mj^i^j
			for i := 1; i <= len(participants); i++ {
				// A_mj
				A_ij := new(btcec.JacobianPoint)
				polynomialCommitments[i][j].AsJacobian(A_ij)
				btcec.AddNonConst(agg, A_ij, agg)
			}
		}(j)
		wg.Wait()
		aggregateCommitments[j] = agg
	}
	logger.Printf("aggregateCommitments takes: %v\n", time.Since(timeNow))

	// All the same for other participants
	timeNow = time.Now()
	for i := 0; i < 1; i++ {
		participant := participants[i]
		// calculate public signing shares of other participants
		for j := 0; j < n; j++ {
			participant.CalculatePublicSigningShares(aggregateCommitments, j+1)
		}
	}
	logger.Printf("CalculatePublicSigningShares takes: %v\n", time.Since(timeNow))

	// verify correct calculation of public signing shares
	// All the same for other participants
	timeNow = time.Now()
	for i := 0; i < 1; i++ {
		participant := participants[i]
		// verify public signing shares of other participants
		for j := 0; j < n; j++ {
			assert.Equal(t, participant.PublicSigningShares[j+1], participants[j].PublicSigningShares[j+1])
		}
	}
	logger.Printf("Comparing takes: %v\n", time.Since(timeNow))
}
