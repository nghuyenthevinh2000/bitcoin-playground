package benchmark

import (
	"fmt"
	"log"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/nghuyenthevinh2000/bitcoin-playground/testhelper"
	"github.com/stretchr/testify/assert"
)

// go test -benchmem -run=^$ -bench ^BenchmarkFrostDKG$ github.com/nghuyenthevinh2000/bitcoin-playground/benchmark
func BenchmarkFrostDKG(b *testing.B) {
	test_suite := []struct {
		n         int64
		threshold int64
	}{
		{
			n:         100,
			threshold: 70,
		},
		{
			n:         500,
			threshold: 350,
		},
		{
			n:         1000,
			threshold: 700,
		},
		{
			n:         2000,
			threshold: 1400,
		},
		{
			n:         4000,
			threshold: 2800,
		},
		{
			n:         8000,
			threshold: 5600,
		},
	}

	for _, test := range test_suite {
		test_name := fmt.Sprintf("frost-dkg-%d/%d", test.threshold, test.n)
		b.Run(test_name, func(b *testing.B) {
			RunFrostDKG(test_name, test.n, test.threshold, b)
		})
	}
}

// go test -benchmem -run=^$ -bench ^BenchmarkWstsDKG$ github.com/nghuyenthevinh2000/bitcoin-playground/benchmark
func BenchmarkWstsDKG(b *testing.B) {

	// participant - keys ratio: 1 - 5
	test_suite := []struct {
		n_p       int64
		n_keys    int64
		threshold int64
	}{
		{
			n_p:       20,
			n_keys:    100,
			threshold: 70,
		},
		{
			n_p:       100,
			n_keys:    500,
			threshold: 350,
		},
		{
			n_p:       200,
			n_keys:    1000,
			threshold: 700,
		},
		{
			n_p:       400,
			n_keys:    2000,
			threshold: 1400,
		},
		{
			n_p:       800,
			n_keys:    4000,
			threshold: 2800,
		},
		{
			n_p:       1600,
			n_keys:    8000,
			threshold: 5600,
		},
	}

	for _, test := range test_suite {
		test_name := fmt.Sprintf("wsts-dkg-%d/%d/%d", test.threshold, test.n_keys, test.n_p)
		b.Run(test_name, func(b *testing.B) {
			RunWstsDKG(test_name, test.n_p, test.n_keys, test.threshold, b)
		})
	}
}

// go test -benchmem -run=^$ -bench ^BenchmarkFrostDKG$ github.com/nghuyenthevinh2000/bitcoin-playground/benchmark
func RunFrostDKG(name string, n, threshold int64, b *testing.B) {
	suite := testhelper.TestSuite{}
	suite.SetupBenchmarkStaticSimNetSuite(b, log.Default())

	// frost
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
	// suite.LogBenchmarkThreadSafeReport("ms/secret-proofs", float64(time.Since(time_now).Milliseconds()), true)

	// calculate secret shares
	secret_shares_map := make(map[int64]map[int64]*btcec.ModNScalar)
	for i := int64(0); i < n; i++ {
		secret_shares_map[i+1] = make(map[int64]*btcec.ModNScalar)
	}

	// time_now = time.Now()
	var wg sync.WaitGroup
	for i := int64(0); i < n; i++ {
		wg.Add(1)
		go func(i int64) {
			defer wg.Done()
			participants[i].CalculateSecretShares()
		}(i)
	}
	wg.Wait()
	// suite.LogBenchmarkThreadSafeReport("ms/calculate-secret-shares", float64(time.Since(time_now).Milliseconds()), true)

	// distribute to all participants
	for i := int64(0); i < n; i++ {
		for j := int64(0); j < n; j++ {
			secret := participants[i].GetSecretShares(j + 1)
			secret_shares_map[j+1][i+1] = secret
		}
	}

	// derive power map
	for i := int64(0); i < n; i++ {
		wg.Add(1)
		go func(i int64) {
			defer wg.Done()
			participants[i].DerivePowerMap()
		}(i)
	}
	wg.Wait()

	time_now = time.Now()
	for i := int64(0); i < 1; i++ {
		// try out batch verification of secret shares
		wg.Add(1)
		go func(i int64) {
			defer wg.Done()
			participants[i].VerifyBatchPublicSecretShares(secret_shares_map[participants[i].Position], uint32(participants[i].Position))
		}(i)
	}
	wg.Wait()
	suite.LogBenchmarkThreadSafeReport("ms/verify-batch-public-secret-shares", float64(time.Since(time_now).Milliseconds()), true)

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
	// suite.LogBenchmarkThreadSafeReport("ms/calculate-internal-public-signing-shares", float64(time.Since(time_now).Milliseconds()), true)

	// calculate public signing shares

	// This operation is too heavy to be done on a single machine simulating all participants.
	// In a distributed settings, each participant will independently calculate this value and derive the same value.
	// So, it is OK to copy the value from the first participant to all other participants.
	// If someone wants to verify, they can uncomment the same functionallity in the loop below.
	time_now = time.Now()
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
	suite.LogBenchmarkThreadSafeReport("ms/derive-external-q-w-map", float64(time.Since(time_now).Milliseconds()), true)

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
			participants[i].CalculateBatchPublicSigningShares(map[int64]bool{i + 1: true})
		}(i)
	}
	wg.Wait()
	// suite.LogBenchmarkThreadSafeReport("ms/calculate-batch-public-signing-shares", float64(time.Since(time_now).Milliseconds()), true)

	// calculate group public key
	time_now = time.Now()
	for i := int64(0); i < n; i++ {
		wg.Add(1)
		go func(i int64) {
			defer wg.Done()
			participant := participants[i]
			participant.CalculateGroupPublicKey()
		}(i)
	}
	wg.Wait()
	// suite.LogBenchmarkThreadSafeReport("ms/calculate-group-public-key", float64(time.Since(time_now).Milliseconds()), true)

	b.StopTimer()

	// verify correct calculation of public signing shares
	for i := int64(0); i < n; i++ {
		participant := participants[i]

		// verify public signing shares of other participants
		for j := int64(0); j < n; j++ {
			if i == j {
				continue
			}

			assert.Equal(suite.T, participant.GetPublicSigningShares(i+1), participants[j].GetPublicSigningShares(i+1))
		}
	}

	// dump logs
	suite.FlushBenchmarkThreadSafeReport()
}

func RunWstsDKG(name string, n_p, n_keys, threshold int64, b *testing.B) {
	suite := testhelper.TestSuite{}
	suite.SetupBenchmarkStaticSimNetSuite(b, log.Default())

	// wsts participant
	participants := make([]*testhelper.WstsParticipant, n_p)
	logger := log.Default()
	for i := int64(0); i < n_p; i++ {
		frost := testhelper.NewFrostParticipant(&suite, logger, n_keys, threshold, i+1, nil)
		participants[i] = testhelper.NewWSTSParticipant(&suite, n_p, frost)
	}

	// update polynomial commitments
	for i := int64(0); i < n_p; i++ {
		for j := int64(0); j < n_p; j++ {
			if i == j {
				continue
			}
			participant := participants[j]
			participant.Frost.UpdatePolynomialCommitments(i+1, participants[i].Frost.PolynomialCommitments[i+1])
		}
	}

	// update key ranges
	keys := suite.DeriveSharesOfKeys(n_p, n_keys)
	range_keys := suite.DeriveRangeOfKeys(keys)
	for i := int64(0); i < n_p; i++ {
		for j := range_keys[i+1][0]; j < range_keys[i+1][1]; j++ {
			participants[i].Keys[j] = true
		}
	}

	// generate challenges
	b.ResetTimer()
	b.StartTimer()
	time_now := time.Now()
	for i := int64(0); i < n_p; i++ {
		participant := participants[i]
		challenge := participant.Frost.CalculateSecretProofs([32]byte{})
		participant.Frost.VerifySecretProofs([32]byte{}, challenge, i+1, participant.Frost.PolynomialCommitments[participant.Frost.Position][0])
	}
	// suite.LogBenchmarkThreadSafeReport("ms/secret-proofs", float64(time.Since(time_now).Milliseconds()), true)

	// calculate secret shares

	time_now = time.Now()
	var wg sync.WaitGroup
	for i := int64(0); i < n_p; i++ {
		wg.Add(1)
		go func(i int64) {
			defer wg.Done()
			participants[i].Frost.CalculateSecretShares()
		}(i)
	}
	wg.Wait()
	// suite.LogBenchmarkThreadSafeReport("ms/calculate-secret-shares", float64(time.Since(time_now).Milliseconds()), true)

	// distribute to all participants
	for i := int64(0); i < n_p; i++ {
		participant := participants[i]

		for j := range participant.Keys {
			secrets := make(map[int64]*btcec.ModNScalar)
			for m := int64(0); m < n_p; m++ {
				secret := participants[m].Frost.GetSecretShares(j)
				secrets[m+1] = secret
			}
			participant.StoreSecretShares(j, secrets)
		}
	}

	// derive power map
	for i := int64(0); i < n_p; i++ {
		wg.Add(1)
		go func(i int64) {
			defer wg.Done()
			participants[i].Frost.DerivePowerMap()
		}(i)
	}
	wg.Wait()

	time_now = time.Now()
	for i := int64(0); i < 1; i++ {
		// try out batch verification of secret shares
		wg.Add(1)
		go func(i int64) {
			defer wg.Done()
			participant := participants[i]
			for j := range participant.Keys {
				participant.Frost.VerifyBatchPublicSecretShares(participant.GetSecretSharesMap(j), uint32(j))
			}
		}(i)
	}
	wg.Wait()
	suite.LogBenchmarkThreadSafeReport("ms/verify-batch-public-secret-shares", float64(time.Since(time_now).Milliseconds()), true)

	// calculate signing shares
	for i := int64(0); i < n_p; i++ {
		participant := participants[i]
		wg.Add(1)
		go func(i int64) {
			defer wg.Done()
			participant.CalculateSigningShares()
		}(i)
	}
	wg.Wait()

	// calculate public signing shares
	time_now = time.Now()
	for i := int64(0); i < n_p; i++ {
		wg.Add(1)
		go func(i int64) {
			defer wg.Done()
			participant := participants[i]
			participant.CalculateInternalPublicSigningShares()
		}(i)
	}
	wg.Wait()
	// suite.LogBenchmarkThreadSafeReport("ms/calculate-internal-public-signing-shares", float64(time.Since(time_now).Milliseconds()), true)

	// calculate public signing shares
	time_now = time.Now()
	participants[0].Frost.DeriveExternalQMap()
	participants[0].Frost.DeriveExternalWMap()

	for i := int64(1); i < n_p; i++ {
		wg.Add(1)
		go func(i int64) {
			defer wg.Done()
			participants[i].Frost.ParseQMap(participants[0].Frost.CopyQMap())
			participants[i].Frost.ParseWMap(participants[0].Frost.CopyWMap())
		}(i)
	}
	wg.Wait()
	suite.LogBenchmarkThreadSafeReport("ms/derive-external-q-w-map", float64(time.Since(time_now).Milliseconds()), true)

	time_now = time.Now()
	for i := int64(0); i < n_p; i++ {
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
	// suite.LogBenchmarkThreadSafeReport("ms/calculate-batch-public-signing-shares", float64(time.Since(time_now).Milliseconds()), true)

	// calculate group public key
	time_now = time.Now()
	for i := int64(0); i < n_p; i++ {
		wg.Add(1)
		go func(i int64) {
			defer wg.Done()
			participant := participants[i]
			participant.Frost.CalculateGroupPublicKey()
		}(i)
	}
	wg.Wait()
	// suite.LogBenchmarkThreadSafeReport("ms/calculate-group-public-key", float64(time.Since(time_now).Milliseconds()), true)

	b.StopTimer()

	// verify correct calculation of public signing shares
	for i := int64(0); i < n_p; i++ {
		participant := participants[i]

		// verify public signing shares of other participants
		for j := int64(0); j < n_p; j++ {
			if i == j {
				continue
			}

			for key := range participant.Keys {
				assert.Equal(suite.T, participant.Frost.GetPublicSigningShares(key), participants[j].Frost.GetPublicSigningShares(key))
			}
		}
	}

	// dump logs
	suite.FlushBenchmarkThreadSafeReport()
}
