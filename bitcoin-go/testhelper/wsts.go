package testhelper

import (
	"math"
	"math/rand"
	"sync"
	"time"

	btcec "github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/assert"
)

type WstsParticipant struct {
	suite *TestSuite

	secret_shares  sync.Map
	signing_shares sync.Map

	N_p   int64
	Keys  map[int64]map[int64]bool
	Frost *FrostParticipant
}

func NewWSTSParticipant(suite *TestSuite, n int64, frost *FrostParticipant) *WstsParticipant {
	wsts := &WstsParticipant{
		suite: suite,
		N_p:   n,
		Keys:  make(map[int64]map[int64]bool),
		Frost: frost,
	}

	return wsts
}

func (wsts *WstsParticipant) LoadKeyRange(keys map[int64]map[int64]bool) {
	wsts.Keys = keys
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
	wsts.Frost.CalculateBatchPublicSigningShares(wsts.Keys[wsts.Frost.Position])
}

func (wsts *WstsParticipant) CalculateInternalPublicSigningShares() {
	var wg sync.WaitGroup
	for key := range wsts.Keys[wsts.Frost.Position] {
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
	for key := range wsts.Keys[wsts.Frost.Position] {
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

// construct z_i = d_i + e_i * p_i + \sum_{K_i} \lambda_{ik} * s_{ik} * c, K_i is the threshold set of honest keys of participant i
// \lambda_i is the Lagrange coefficient for the participant i over the honest participants
// s_i is the long-term secret share of participant i
// c = H(R, Y, m)
// TODO: have not checked for even or odd Y - coordinates
//
// a different variant of partial sign for wsts
func (wsts *WstsParticipant) WeightedPartialSign(signing_index int64, honest_party []int64, message_hash [32]byte, public_nonces map[int64][2]*btcec.PublicKey) *schnorr.Signature {
	// honest keys
	honest_keys := make([]int64, 0)
	for _, index := range honest_party {
		for key := range wsts.Keys[index] {
			honest_keys = append(honest_keys, key)
		}
	}

	// calculate c
	commitment_data := make([]byte, 0)
	commitment_data = append(commitment_data, wsts.Frost.AggrNonceCommitment[signing_index].X.Bytes()[:]...)
	commitment_data = append(commitment_data, schnorr.SerializePubKey(wsts.Frost.GroupPublicKey)...)
	commitment_data = append(commitment_data, message_hash[:]...)
	commitment_hash := chainhash.TaggedHash(chainhash.TagBIP0340Challenge, commitment_data)
	c := new(btcec.ModNScalar)
	c.SetByteSlice(commitment_hash[:])

	// calculate p_i
	p_i_data := make([]byte, 0)
	p_i_data = append(p_i_data, byte(wsts.Frost.Position))
	p_i_data = append(p_i_data, message_hash[:]...)
	for _, i := range honest_party {
		D := new(btcec.JacobianPoint)
		public_nonces[i][0].AsJacobian(D)
		E := new(btcec.JacobianPoint)
		public_nonces[i][1].AsJacobian(E)
		p_i_data = append(p_i_data, D.X.Bytes()[:]...)
		p_i_data = append(p_i_data, E.X.Bytes()[:]...)
	}
	p_i := chainhash.HashB(p_i_data)
	p_i_scalar := new(btcec.ModNScalar)
	p_i_scalar.SetByteSlice(p_i)

	// d_i, e_i: create new instances to avoid modifying the original values
	d_i := new(btcec.ModNScalar).Set(wsts.Frost.nonces[signing_index][0])
	e_i := new(btcec.ModNScalar).Set(wsts.Frost.nonces[signing_index][1])
	// e_i * p_i
	term := new(btcec.ModNScalar).Mul2(e_i, p_i_scalar)
	// d_i + e_i * p_i
	term1 := new(btcec.ModNScalar).Add2(d_i, term)
	R_i := new(btcec.JacobianPoint)
	btcec.ScalarBaseMultNonConst(term1, R_i)
	R_i.ToAffine()

	// some R_i might have even Y coordinate, but total R can have odd Y coordinate
	// thus, we need to negate all d_i and e_i to satisfy even Y coordinate for R
	// this will conflict with any even Y coordinate in R_i
	// this is such dilema that we should not check for oddness in R_i
	if wsts.Frost.AggrNonceCommitment[signing_index].Y.IsOdd() {
		d_i.Negate()
		e_i.Negate()
	}

	// signing for wsts
	z_i := new(btcec.ModNScalar)
	// e_i * p_i
	term = new(btcec.ModNScalar).Mul2(e_i, p_i_scalar)
	// d_i + e_i * p_i
	term1 = new(btcec.ModNScalar).Add2(d_i, term)
	// \sum_{K_i} \lambda_{ik} * s_{ik} * c
	term3 := new(btcec.ModNScalar).SetInt(0)
	wsts.signing_shares.Range(func(key, value interface{}) bool {
		key_index := key.(int64)
		shares := value.(*btcec.ModNScalar)

		s_i := new(btcec.ModNScalar).Set(shares)
		if wsts.Frost.GroupPublicKey.SerializeCompressed()[0] == secp.PubKeyFormatCompressedOdd {
			s_i.Negate()
		}

		// calculate larange coefficient
		lamba := wsts.Frost.suite.CalculateLagrangeCoeff(key_index, honest_keys)
		// \lambda_{ik} * s_{ik} * c
		term2 := new(btcec.ModNScalar).Mul2(lamba, s_i).Mul(c)
		// \sum_{K_i} \lambda_{ik} * s_{ik} * c
		term3.Add(term2)

		return true
	})
	// d_i + e_i * p_i + \sum_{K_i} \lambda_{ik} * s_{ik} * c
	z_i.Add2(term1, term3)

	sig := schnorr.NewSignature(&R_i.X, z_i)

	return sig
}

// verifying the partial signature from each honest participant
// recall that: z_i = d_i + e_i * p_i + \sum_{K_i} \lambda_{ik} * s_{ik} * c
// thus, g^z_i = R_i * g^(\sum_{K_i} \lambda_{ik} * s_{ik} * c) = R_i * \prod_{K_i} Y_{ik}^(\lambda_{ik} * c)
// thus, R_i = g^z_i * \prod_{K_i} Y_{ik}^-(\lambda_{ik} * c)
//
// a different variant of partial sign for wsts
func (wsts *WstsParticipant) WeightedPartialVerification(sig *schnorr.Signature, signing_index, posi int64, message_hash [32]byte, honest_party []int64, signing_verification_shares map[int64]*btcec.PublicKey) bool {
	// honest keys
	honest_keys := make([]int64, 0)
	for _, index := range honest_party {
		for key := range wsts.Keys[index] {
			honest_keys = append(honest_keys, key)
		}
	}

	// derive z and R_X
	sig_bytes := sig.Serialize()
	R_bytes := sig_bytes[0:32]
	R_X := new(btcec.FieldVal)
	R_X.SetByteSlice(R_bytes)
	z_bytes := sig_bytes[32:64]
	z := new(btcec.ModNScalar)
	z.SetByteSlice(z_bytes)

	// calculate c = H(R, Y, m)
	commitment_data := make([]byte, 0)
	commitment_data = append(commitment_data, wsts.Frost.AggrNonceCommitment[signing_index].X.Bytes()[:]...)
	commitment_data = append(commitment_data, schnorr.SerializePubKey(wsts.Frost.GroupPublicKey)...)
	commitment_data = append(commitment_data, message_hash[:]...)
	commitment_hash := chainhash.TaggedHash(chainhash.TagBIP0340Challenge, commitment_data)
	c := new(btcec.ModNScalar)
	c.SetByteSlice(commitment_hash[:])

	c.Negate()

	// calculate \prod_{K_i} Y_{ik}^-(\lambda_{ik} * c)
	prod := new(btcec.JacobianPoint)
	for key_index, shares := range signing_verification_shares {
		Y_i := new(btcec.JacobianPoint)
		shares.AsJacobian(Y_i)
		if wsts.Frost.GroupPublicKey.SerializeCompressed()[0] == secp.PubKeyFormatCompressedOdd {
			Y_i.Y.Negate(1)
			Y_i.Y.Normalize()
		}

		// calculate \lambda_{ik} * -c
		term := new(btcec.ModNScalar)
		lambda := wsts.suite.CalculateLagrangeCoeff(key_index, honest_keys)
		term.Mul2(lambda, c)

		// Y_{ik}^-(\lambda_{ik} * c)
		term1 := new(btcec.JacobianPoint)
		btcec.ScalarMultNonConst(term, Y_i, term1)

		btcec.AddNonConst(prod, term1, prod)
	}

	// g^z_i
	term2 := new(btcec.JacobianPoint)
	btcec.ScalarBaseMultNonConst(z, term2)
	// R_i = g^z_i * \prod_{K_i} Y_{ik}^-(\lambda_{ik} * c)
	R := new(btcec.JacobianPoint)
	btcec.AddNonConst(term2, prod, R)

	// Fail if R is the point at infinity
	is_infinity := false
	if (R.X.IsZero() && R.Y.IsZero()) || R.Z.IsZero() {
		is_infinity = true
	}
	assert.False(wsts.suite.T, is_infinity, "verify partial sig proof: R is the point at infinity")
	if is_infinity {
		return false
	}

	R.ToAffine()

	// verify R point equals provided R_X
	assert.Equal(wsts.suite.T, &R.X, R_X, "verify partial sig proof: R.X does not match provided R_X")
	return R.X.Equals(R_X)
}

// from shares of keys, determine selected keys to pass threshold
func (s *TestSuite) RandomHonestSet(n_p, n_keys int64, keys []int64) []int64 {
	randsource := rand.New(rand.NewSource(time.Now().UnixNano()))
	// determine the number of dishonest participants from 10% to 30% of the total signing power
	n_dishonest_max := int64(math.Floor(float64(n_keys) * 0.3))
	n_dishonest_min := int64(math.Floor(float64(n_keys) * 0.1))
	n_dishonest := randsource.Int63n(n_dishonest_max-n_dishonest_min) + n_dishonest_min

	// randomly select dishonest participants
	dishonest_set := make(map[int64]bool)
	accumulate_dishonest_power := int64(0)
	for accumulate_dishonest_power < n_dishonest {
		dishonest := randsource.Int63n(n_p) + 1
		if _, ok := dishonest_set[dishonest]; ok {
			continue
		}

		accumulate_dishonest_power += keys[dishonest-1]
		dishonest_set[dishonest] = true
	}

	// determine the honest set
	honest_set := make([]int64, 0)
	for i := int64(1); i <= n_p; i++ {
		if _, ok := dishonest_set[i]; !ok {
			honest_set = append(honest_set, i)
		}
	}

	return honest_set
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
