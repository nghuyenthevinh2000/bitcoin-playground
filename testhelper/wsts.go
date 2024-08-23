package testhelper

import (
	"math"
	"math/rand"
	"sync"
	"time"

	btcec "github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/assert"
)

type WstsParticipant struct {
	suite *TestSuite

	secret_shares  sync.Map
	signing_shares sync.Map

	N_p   int64
	Keys  map[int64]bool
	Frost *FrostParticipant
}

func NewWSTSParticipant(suite *TestSuite, n int64, frost *FrostParticipant) *WstsParticipant {
	wsts := &WstsParticipant{
		suite: suite,
		N_p:   n,
		Keys:  make(map[int64]bool),
		Frost: frost,
	}

	return wsts
}

func (wsts *WstsParticipant) StoreSigningShares(key int64, signing_share *btcec.ModNScalar) {
	wsts.signing_shares.Store(key, signing_share)
}

func (wsts *WstsParticipant) GetSigningShares(key int64) *btcec.ModNScalar {
	ss, ok := wsts.signing_shares.Load(key)
	assert.True(wsts.suite.T, ok)
	return ss.(*btcec.ModNScalar)
}

func (wsts *WstsParticipant) StoreSecretShares(key int64, secret_shares map[int64]*btcec.ModNScalar) {
	wsts.secret_shares.Store(key, secret_shares)
}

func (wsts *WstsParticipant) GetSecretSharesItem(key, j int64) *btcec.ModNScalar {
	item, ok := wsts.secret_shares.Load(key)
	assert.True(wsts.suite.T, ok)
	return item.(map[int64]*btcec.ModNScalar)[j]
}

func (wsts *WstsParticipant) GetSecretSharesMap(key int64) map[int64]*btcec.ModNScalar {
	ss_map, ok := wsts.secret_shares.Load(key)
	assert.True(wsts.suite.T, ok)
	return ss_map.(map[int64]*btcec.ModNScalar)
}

func (wsts *WstsParticipant) CalculateBatchPublicSigningShares() {
	wsts.Frost.CalculateBatchPublicSigningShares(wsts.Keys)
}

func (wsts *WstsParticipant) CalculateInternalPublicSigningShares() {
	var wg sync.WaitGroup
	for key := range wsts.Keys {
		wg.Add(1)
		go func(key int64) {
			defer wg.Done()
			ss := wsts.GetSigningShares(key)
			wsts.Frost.CalculateInternalPublicSigningShares(ss, key)
		}(key)
	}
	wg.Wait()
}

func (wsts *WstsParticipant) CalculateSigningShares() {
	var wg sync.WaitGroup
	for key := range wsts.Keys {
		wg.Add(1)
		go func(key int64) {
			defer wg.Done()
			shares := wsts.GetSecretSharesMap(key)
			signing_share := new(btcec.ModNScalar)
			signing_share.SetInt(0)

			for _, share := range shares {
				signing_share.Add(share)
			}

			wsts.StoreSigningShares(key, signing_share)
		}(key)
	}
	wg.Wait()
}

func (s *TestSuite) DeriveSharesOfKeys(n_p, n_keys int64) []int64 {
	randsource := rand.New(rand.NewSource(time.Now().UnixNano()))
	total := int64(0)
	shares := make([]float64, n_p)
	keys := make([]int64, n_p)
	// randomly distribute shares of keys to participants
	for i := int64(0); i < n_p; i++ {
		rand_vp := randsource.Int63n(1000000)
		total += rand_vp
		shares[i] = float64(rand_vp)
	}

	total_keys := int64(0)
	for i := int64(1); i < n_p; i++ {
		term := (shares[i] / float64(total)) * float64(n_keys)
		keys[i] = int64(math.Floor(term))

		if keys[i] == 0 {
			keys[i] = 1
		}

		total_keys += keys[i]
	}
	keys[0] = n_keys - total_keys
	assert.Greater(s.T, keys[0], int64(0))

	return keys
}

func (s *TestSuite) DeriveRangeOfKeys(keys []int64) map[int64][2]int64 {
	n_p := int64(len(keys))
	range_keys := make(map[int64][2]int64)
	start := int64(1)

	// randomly distribute keys to participants
	for i := int64(0); i < n_p; i++ {
		end := start + keys[i]
		range_keys[i+1] = [2]int64{start, end}
		start = end
	}

	return range_keys
}
