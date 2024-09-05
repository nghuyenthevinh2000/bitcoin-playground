package benchmark

import (
	"fmt"
	"log"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
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
			n:         1500,
			threshold: 1050,
		},
		{
			n:         2000,
			threshold: 1400,
		},
		{
			n:         4000,
			threshold: 2800,
		},
	}

	for _, test := range test_suite {
		test_name := fmt.Sprintf("frost-dkg-%d/%d", test.threshold, test.n)
		b.Run(test_name, func(b *testing.B) {
			RunFrostDKG(test_name, test.n, test.threshold, b)
		})
	}
}

// go test -timeout 1h -run ^TestBenchmarkWstsDKG$ github.com/nghuyenthevinh2000/bitcoin-playground/benchmark
func TestBenchmarkWstsDKG(t *testing.T) {

	test_suite := []*WstsBenchmark{
		{
			n_p:       100,
			n_keys:    500,
			threshold: 350,
		},
		{
			n_p:       100,
			n_keys:    1000,
			threshold: 700,
		},
		{
			n_p:       100,
			n_keys:    1500,
			threshold: 1050,
		},
		{
			n_p:       100,
			n_keys:    2000,
			threshold: 1400,
		},
		{
			n_p:       100,
			n_keys:    2500,
			threshold: 1750,
		},
		{
			n_p:       100,
			n_keys:    3000,
			threshold: 2100,
		},
		{
			n_p:       200,
			n_keys:    1000,
			threshold: 700,
		},
		{
			n_p:       200,
			n_keys:    1500,
			threshold: 1050,
		},
		{
			n_p:       200,
			n_keys:    2000,
			threshold: 1400,
		},
		{
			n_p:       200,
			n_keys:    2500,
			threshold: 1750,
		},
		{
			n_p:       200,
			n_keys:    3000,
			threshold: 2100,
		},
	}

	for _, wsts := range test_suite {
		wsts.suite = testhelper.TestSuite{}
		wsts.suite.SetupStaticSimNetSuite(t, log.Default())

		test_name := fmt.Sprintf("wsts-dkg-%d/%d/%d", wsts.threshold, wsts.n_keys, wsts.n_p)
		t.Run(test_name, func(t *testing.T) {
			wsts.RunWstsDKG(test_name, t)
		})

		test_name = fmt.Sprintf("wsts-signing-%d/%d/%d", wsts.threshold, wsts.n_keys, wsts.n_p)
		t.Run(test_name, func(t *testing.T) {
			wsts.RunWstsSigning(test_name, t)
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

type WstsBenchmark struct {
	suite        testhelper.TestSuite
	n_p          int64
	n_keys       int64
	threshold    int64
	key_shares   []int64
	participants []*testhelper.WstsParticipant
}

func (wsts *WstsBenchmark) RunWstsDKG(name string, t *testing.T) {
	// wsts participant
	wsts.participants = make([]*testhelper.WstsParticipant, wsts.n_p)
	logger := log.Default()
	for i := int64(0); i < wsts.n_p; i++ {
		frost := testhelper.NewFrostParticipant(&wsts.suite, logger, wsts.n_keys, wsts.threshold, i+1, nil)
		wsts.participants[i] = testhelper.NewWSTSParticipant(&wsts.suite, wsts.n_p, frost)
	}

	// update polynomial commitments
	for i := int64(0); i < wsts.n_p; i++ {
		for j := int64(0); j < wsts.n_p; j++ {
			if i == j {
				continue
			}
			participant := wsts.participants[j]
			participant.Frost.UpdatePolynomialCommitments(i+1, wsts.participants[i].Frost.PolynomialCommitments[i+1])
		}
	}

	// update key ranges
	wsts.key_shares = wsts.suite.DeriveSharesOfKeys(wsts.n_p, wsts.n_keys)
	range_keys := wsts.suite.DeriveRangeOfKeys(wsts.key_shares)
	keys := make(map[int64]map[int64]bool)
	for i := int64(0); i < wsts.n_p; i++ {
		keys[i+1] = make(map[int64]bool)
		for j := range_keys[i+1][0]; j < range_keys[i+1][1]; j++ {
			keys[i+1][j] = true
		}
	}

	for i := int64(0); i < wsts.n_p; i++ {
		wsts.participants[i].LoadKeyRange(keys)
	}

	// generate challenges
	time_all := time.Now()
	for i := int64(0); i < wsts.n_p; i++ {
		participant := wsts.participants[i]
		challenge := participant.Frost.CalculateSecretProofs([32]byte{})
		participant.Frost.VerifySecretProofs([32]byte{}, challenge, i+1, participant.Frost.PolynomialCommitments[participant.Frost.Position][0])
	}
	// suite.LogBenchmarkThreadSafeReport("ms/secret-proofs", float64(time.Since(time_now).Milliseconds()), true)

	// calculate secret shares

	time_now := time.Now()
	var wg sync.WaitGroup
	for i := int64(0); i < wsts.n_p; i++ {
		wg.Add(1)
		go func(i int64) {
			defer wg.Done()
			wsts.participants[i].Frost.CalculateSecretShares()
		}(i)
	}
	wg.Wait()
	// suite.LogBenchmarkThreadSafeReport("ms/calculate-secret-shares", float64(time.Since(time_now).Milliseconds()), true)

	// distribute to all participants
	for i := int64(0); i < wsts.n_p; i++ {
		participant := wsts.participants[i]

		for j := range participant.Keys[i+1] {
			secrets := make(map[int64]*btcec.ModNScalar)
			for m := int64(0); m < wsts.n_p; m++ {
				secret := wsts.participants[m].Frost.GetSecretShares(j)
				secrets[m+1] = secret
			}
			participant.StoreSecretShares(j, secrets)
		}
	}

	// derive power map
	for i := int64(0); i < wsts.n_p; i++ {
		wg.Add(1)
		go func(i int64) {
			defer wg.Done()
			wsts.participants[i].Frost.DerivePowerMap()
		}(i)
	}
	wg.Wait()

	time_now = time.Now()
	for i := int64(0); i < 1; i++ {
		// try out batch verification of secret shares
		wg.Add(1)
		go func(i int64) {
			defer wg.Done()
			participant := wsts.participants[i]
			for j := range participant.Keys[i+1] {
				participant.Frost.VerifyBatchPublicSecretShares(participant.GetSecretSharesMap(j), uint32(j))
			}
		}(i)
	}
	wg.Wait()
	wsts.suite.LogBenchmarkThreadSafeReport("ms/verify-batch-public-secret-shares", float64(time.Since(time_now).Milliseconds()), true)

	// calculate signing shares
	for i := int64(0); i < wsts.n_p; i++ {
		participant := wsts.participants[i]
		wg.Add(1)
		go func(i int64) {
			defer wg.Done()
			participant.CalculateSigningShares()
		}(i)
	}
	wg.Wait()

	// calculate public signing shares
	time_now = time.Now()
	for i := int64(0); i < wsts.n_p; i++ {
		wg.Add(1)
		go func(i int64) {
			defer wg.Done()
			participant := wsts.participants[i]
			participant.CalculateInternalPublicSigningShares()
		}(i)
	}
	wg.Wait()
	// suite.LogBenchmarkThreadSafeReport("ms/calculate-internal-public-signing-shares", float64(time.Since(time_now).Milliseconds()), true)

	// calculate public signing shares
	time_now = time.Now()
	wsts.participants[0].Frost.DeriveExternalQMap()
	wsts.participants[0].Frost.DeriveExternalWMap()

	for i := int64(1); i < wsts.n_p; i++ {
		wg.Add(1)
		go func(i int64) {
			defer wg.Done()
			wsts.participants[i].Frost.ParseQMap(wsts.participants[0].Frost.CopyQMap())
			wsts.participants[i].Frost.ParseWMap(wsts.participants[0].Frost.CopyWMap())
		}(i)
	}
	wg.Wait()
	wsts.suite.LogBenchmarkThreadSafeReport("ms/derive-external-q-w-map", float64(time.Since(time_now).Milliseconds()), true)

	time_now = time.Now()
	for i := int64(0); i < wsts.n_p; i++ {
		wg.Add(1)
		go func(i int64) {
			defer wg.Done()
			// If someone wants to see if the calculation is correct independently, they can uncomment the following lines.
			// You will want to change n, and t to smaller value.
			// participants[i].DeriveExternalQMap()
			// participants[i].DeriveExternalWMap()

			// calculate public signing shares of other participants
			wsts.participants[i].CalculateBatchPublicSigningShares()
		}(i)
	}
	wg.Wait()
	// suite.LogBenchmarkThreadSafeReport("ms/calculate-batch-public-signing-shares", float64(time.Since(time_now).Milliseconds()), true)

	// calculate group public key
	time_now = time.Now()
	for i := int64(0); i < wsts.n_p; i++ {
		wg.Add(1)
		go func(i int64) {
			defer wg.Done()
			participant := wsts.participants[i]
			participant.Frost.CalculateGroupPublicKey()
		}(i)
	}
	wg.Wait()
	// suite.LogBenchmarkThreadSafeReport("ms/calculate-group-public-key", float64(time.Since(time_now).Milliseconds()), true)

	wsts.suite.LogBenchmarkThreadSafeReport("ms/wsts-dkg", float64(time.Since(time_all).Milliseconds()), false)

	// verify correct calculation of public signing shares
	for i := int64(0); i < wsts.n_p; i++ {
		participant := wsts.participants[i]

		// verify public signing shares of other participants
		for j := int64(0); j < wsts.n_p; j++ {
			if i == j {
				continue
			}

			for key := range participant.Keys[i+1] {
				assert.Equal(wsts.suite.T, participant.Frost.GetPublicSigningShares(key), wsts.participants[j].Frost.GetPublicSigningShares(key))
			}
		}
	}

	// dump logs
	wsts.suite.FlushBenchmarkThreadSafeReport()
}

func (wsts *WstsBenchmark) RunWstsSigning(name string, t *testing.T) {
	signing_index := int64(0)

	// honest_set[0] key_share is honest_keys[0]
	honest_set := wsts.suite.RandomHonestSet(wsts.n_p, wsts.n_keys, wsts.key_shares)

	time_all := time.Now()

	// Stage 1: Nonce generation
	public_nonces := make(map[int64][2]*btcec.PublicKey)
	for _, participant := range wsts.participants {
		nonces := participant.Frost.GenerateSigningNonces(1)
		public_nonces[participant.Frost.Position] = nonces[signing_index]
	}

	for _, participant_index := range honest_set {
		participant := wsts.participants[participant_index-1]
		participant.Frost.CalculatePublicNonceCommitments(signing_index, honest_set, [32]byte{}, public_nonces)
	}

	// Stage 2: Partial signature generation (Benchmark ends here for individual participants)
	partial_signatures := make(map[int64]*schnorr.Signature)
	for _, participant_index := range honest_set {
		participant := wsts.participants[participant_index-1]

		sig := participant.WeightedPartialSign(signing_index, honest_set, [32]byte{}, public_nonces)
		partial_signatures[participant.Frost.Position] = sig
	}

	var wg sync.WaitGroup
	for _, participant_index := range honest_set {
		wg.Add(1)
		go func(participant_index int64) {
			defer wg.Done()
			participant := wsts.participants[participant_index-1]
			for posi, p_sig := range partial_signatures {
				if posi == participant.Frost.Position {
					continue
				}

				public_signing_share := make(map[int64]*btcec.PublicKey)
				for key := range participant.Keys[posi] {
					public_signing_share[key] = participant.Frost.GetPublicSigningShares(key)
				}

				// Verify partial signatures
				ok := participant.WeightedPartialVerification(p_sig, signing_index, posi, [32]byte{}, honest_set, public_signing_share)
				assert.True(wsts.suite.T, ok, fmt.Sprintf("participant %d: failed to verify partial signature of %d", participant.Frost.Position, posi))
			}
		}(participant_index)
	}
	wg.Wait()

	wsts.suite.LogBenchmarkThreadSafeReport("ms/wsts-signing", float64(time.Since(time_all).Milliseconds()), false)
}
