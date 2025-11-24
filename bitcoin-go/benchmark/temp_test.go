package benchmark

import (
	"fmt"
	"log"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/nghuyenthevinh2000/bitcoin-playground/testhelper"
	"github.com/stretchr/testify/assert"
)

// go test -v -timeout 1h -run ^TestDebugBenchmarkWstsDKG$ github.com/nghuyenthevinh2000/bitcoin-playground/benchmark
func TestDebugBenchmarkWstsDKG(t *testing.T) {
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
			n_p:       150,
			n_keys:    1000,
			threshold: 700,
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

		test_name = fmt.Sprintf("wsts-sig-aggregate-%d/%d/%d", wsts.threshold, wsts.n_keys, wsts.n_p)
		t.Run(test_name, func(t *testing.T) {
			wsts.RunWstsSigAggregate(test_name, t)
		})
	}
}

// aggregate partial signatures
func (wsts *WstsBenchmark) RunWstsSigAggregate(name string, t *testing.T) {
	signing_index := int64(0)

	aggr := new(btcec.ModNScalar)
	var honest int64
	for posi, p_sig := range wsts.partial_sig {
		// extract partial signature
		sig := new(btcec.ModNScalar)
		sig.SetByteSlice(p_sig.Serialize()[32:64])
		aggr.Add(sig)
		honest = posi
	}

	sig := schnorr.NewSignature(&wsts.participants[honest-1].Frost.AggrNonceCommitment[signing_index].X, aggr)
	message_hash := make([]byte, 32)
	res := sig.Verify(message_hash, wsts.participants[honest].Frost.GroupPublicKey)
	assert.True(t, res, "signature verification failed")
}
