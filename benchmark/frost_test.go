package benchmark

import (
	"log"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/nghuyenthevinh2000/bitcoin-playground/testhelper"
	"github.com/stretchr/testify/assert"
)

// go test -benchmem -run=^$ -bench ^BenchmarkFrostSignature$ github.com/nghuyenthevinh2000/bitcoin-playground/benchmark
func BenchmarkFrostSignature(b *testing.B) {
	suite := testhelper.TestSuite{}
	suite.SetupBenchmarkStaticSimNetSuite(b, log.Default())

	// frost
	n := int64(200)
	threshold := int64(140)
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
	b.ResetTimer()
	b.StartTimer()
	time_now := time.Now()
	for i := int64(0); i < n; i++ {
		participant := participants[i]
		challenge := participant.CalculateSecretProofs([32]byte{})
		participant.VerifySecretProofs([32]byte{}, challenge, i+1, participant.PolynomialCommitments[participant.Position][0])
	}
	b.ReportMetric(float64(time.Since(time_now).Milliseconds()), "ms/secret-proofs")

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

	time_now = time.Now()
	var wg sync.WaitGroup
	for i := int64(0); i < n; i++ {
		wg.Add(1)
		go func(i int64) {
			defer wg.Done()
			participants[i].CalculateSecretShares()
		}(i)
	}
	wg.Wait()

	for i := int64(0); i < n; i++ {
		// try out batch verification of secret shares
		wg.Add(1)
		go func(i int64) {
			defer wg.Done()
			participants[i].DerivePowerMap()

			participants[i].VerifyBatchPublicSecretShares(secret_shares_map[participants[i].Position], uint32(participants[i].Position))
		}(i)
	}
	wg.Wait()
	b.ReportMetric(float64(time.Since(time_now).Milliseconds()), "ms/verify-batch-public-secret-shares")

	// distribute signing shares
	signing_shares_map := make(map[int64]*btcec.ModNScalar)
	for i := int64(0); i < n; i++ {
		participant := participants[i]
		signing_shares_map[participant.Position] = new(btcec.ModNScalar)
		signing_shares_map[participant.Position].SetInt(0)

		for j := int64(0); j < n; j++ {
			secret := secret_shares_map[participant.Position][j+1]
			signing_shares_map[participant.Position].Add(secret)
		}
	}

	// calculate public signing shares
	time_now = time.Now()
	for i := int64(0); i < n; i++ {
		wg.Add(1)
		go func(i int64) {
			defer wg.Done()
			participant := participants[i]
			participant.CalculateInternalPublicSigningShares(signing_shares_map[participant.Position], participant.Position)
		}(i)
	}
	wg.Wait()
	b.ReportMetric(float64(time.Since(time_now).Milliseconds()), "ms/calculate-internal-public-signing-shares")

	// calculate public signing shares

	// This operation is too heavy to be done on a single machine simulating all participants.
	// In a distributed settings, each participant will independently calculate this value and derive the same value.
	// So, it is OK to copy the value from the first participant to all other participants.
	// If someone wants to verify, they can uncomment the same functionallity in the loop below.
	participants[0].DeriveExternalQMap()
	participants[0].DeriveExternalWMap()

	for i := int64(1); i < n; i++ {
		wg.Add(1)
		go func(i int64) {
			defer wg.Done()
			participants[i].ParseQMap(participants[0].CopyQMap())
			participants[i].ParseWMap(participants[0].CopyWMap())
		}(i)
	}
	wg.Wait()

	time_now = time.Now()
	for i := int64(0); i < n; i++ {
		wg.Add(1)
		go func(i int64) {
			defer wg.Done()
			// If someone wants to see if the calculation is correct independently, they can uncomment the following lines.
			// You will want to change n, and t to smaller value.
			// participants[i].DeriveExternalQMap()
			// participants[i].DeriveExternalWMap()

			// calculate public signing shares of other participants
			participants[i].CalculateBatchPublicSigningShares()
		}(i)
	}
	wg.Wait()
	b.ReportMetric(float64(time.Since(time_now).Milliseconds()), "ms/calculate-batch-public-signing-shares")

	// verify correct calculation of public signing shares
	for i := int64(0); i < n; i++ {
		participant := participants[i]

		// verify public signing shares of other participants
		for j := int64(0); j < n; j++ {
			if i == j {
				continue
			}

			assert.Equal(suite.T, participant.PublicSigningShares[i+1], participants[j].PublicSigningShares[i+1])
		}
	}

	b.StopTimer()
	// dump logs
	suite.FlushBenchmarkThreadSafeReport()
}
