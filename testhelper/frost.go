package testhelper

import (
	"log"
	"sync"
	"time"

	btcec "github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/assert"
)

// seem like FROST will be hevily used as a bitcoin building block
// thus, it will be re - used in many tests
//
// TODO: many math operations here probably needs to be optimized and benchmarked

var (
	TagFROSTChallenge = []byte("FROST/challenge")
)

// multiple signing usages are meant to sign multiple messages with this Frost setup
type FrostParticipant struct {
	suite  *TestSuite
	logger *log.Logger

	N         int64
	Threshold int64
	Position  int64

	secretSharesMutex sync.Mutex

	secretPolynomial []*btcec.ModNScalar
	secretShares     []*btcec.ModNScalar
	// nonce commitments for multiples signing usages
	nonces [][2]*btcec.ModNScalar

	PolynomialCommitments map[int64][]*btcec.PublicKey
	PublicSigningShares   map[int64]*btcec.PublicKey
	GroupPublicKey        *btcec.PublicKey
	// contains the nonce commitments for multiple signing usages
	NonceCommitments [][2]*btcec.PublicKey
	// contains the aggregated nonce commitments for multiple signing usages
	AggrNonceCommitment map[int64]*btcec.JacobianPoint
}

func NewFrostParticipant(suite *TestSuite, logger *log.Logger, n, Threshold, posi int64, secret *btcec.ModNScalar) *FrostParticipant {
	frost := &FrostParticipant{
		suite:                 suite,
		logger:                logger,
		N:                     n,
		Threshold:             Threshold,
		Position:              posi,
		PolynomialCommitments: make(map[int64][]*btcec.PublicKey),
		PublicSigningShares:   make(map[int64]*btcec.PublicKey),
		AggrNonceCommitment:   make(map[int64]*secp.JacobianPoint),
	}

	// generate secret polynomial
	frost.secretPolynomial = suite.GeneratePolynomial(Threshold)
	if secret != nil {
		frost.secretPolynomial[0] = secret
	}
	// generate public polynomial commitments
	frost.PolynomialCommitments[posi] = frost.generatePedersenCommitments()

	return frost
}

// calculate A(k) = g^a_k
func (p *FrostParticipant) generatePedersenCommitments() []*btcec.PublicKey {
	commitments := make([]*btcec.PublicKey, p.Threshold+1)
	for i := int64(0); i <= p.Threshold; i++ {
		// g^a_k
		point := new(btcec.JacobianPoint)
		btcec.ScalarBaseMultNonConst(p.secretPolynomial[i], point)
		point.ToAffine()
		commitments[i] = btcec.NewPublicKey(&point.X, &point.Y)
	}
	return commitments
}

func (p *FrostParticipant) UpdatePolynomialCommitments(posi int64, commitments []*btcec.PublicKey) {
	p.PolynomialCommitments[posi] = commitments
}

// calculating secret proofs challenge
// c = H(i, stamp, A_i, R_i)
func (p *FrostParticipant) CalculateSecretProofsChallenge(context_hash [32]byte, R_x *btcec.FieldVal, position int64, secretCommitments *btcec.PublicKey) *btcec.ModNScalar {
	// c = H(i, stamp, A_i, R_i)
	commitment_data := make([]byte, 0)
	commitment_data = append(commitment_data, byte(position))
	commitment_data = append(commitment_data, context_hash[:]...)
	commitment_data = append(commitment_data, schnorr.SerializePubKey(secretCommitments)...)
	commitment_data = append(commitment_data, R_x.Bytes()[:]...)

	commitment_hash := chainhash.TaggedHash(TagFROSTChallenge, commitment_data)
	c := new(btcec.ModNScalar)
	c.SetByteSlice(commitment_hash[:])

	return c
}

func (p *FrostParticipant) CalculateSecretProofs(context_hash [32]byte) *schnorr.Signature {
	nonce := p.suite.Generate32BSeed()
	k := new(btcec.ModNScalar)
	k.SetBytes(&nonce)
	R := new(btcec.JacobianPoint)
	btcec.ScalarBaseMultNonConst(k, R)
	R.ToAffine()
	// BIP340 requires that Y coordinate is even
	if R.Y.IsOdd() {
		k.Negate()
	}

	// BIP340 requires that Y coordinate is even
	// Warning: btcec.ModNScalar is stored as pointer, so we need to create a copy else the original value will be modified
	secret := new(btcec.ModNScalar).Set(p.secretPolynomial[0])
	secret_commitment_bytes := p.PolynomialCommitments[p.Position][0].SerializeCompressed()
	if secret_commitment_bytes[0] == secp.PubKeyFormatCompressedOdd {
		secret.Negate()
	}

	c := p.CalculateSecretProofsChallenge(context_hash, &R.X, p.Position, p.PolynomialCommitments[p.Position][0])

	s_scalar := new(btcec.ModNScalar).Mul2(secret, c).Add(k)
	sig := schnorr.NewSignature(&R.X, s_scalar)

	// self verification
	p.VerifySecretProofs(context_hash, sig, p.Position, p.PolynomialCommitments[p.Position][0])

	return sig
}

func (p *FrostParticipant) VerifySecretProofs(context_hash [32]byte, secret_proof *schnorr.Signature, position int64, secretCommitments *btcec.PublicKey) {
	// retrive (R, s) from secret Schnorr proof
	secret_proof_bytes := secret_proof.Serialize()
	R_bytes := secret_proof_bytes[0:32]
	R_x := new(btcec.FieldVal)
	R_x.SetByteSlice(R_bytes)
	s_bytes := secret_proof_bytes[32:64]
	s := new(btcec.ModNScalar)
	s.SetByteSlice(s_bytes)

	c := p.CalculateSecretProofsChallenge(context_hash, R_x, position, secretCommitments)

	// making even the public key Y coordinate
	secret_commitment_bytes := schnorr.SerializePubKey(secretCommitments)
	secret_commitment_pubkey, err := schnorr.ParsePubKey(secret_commitment_bytes)
	assert.Nil(p.suite.T, err)

	R := new(btcec.JacobianPoint)
	// A_i0^-c
	secret_commitment_point := new(btcec.JacobianPoint)
	secret_commitment_pubkey.AsJacobian(secret_commitment_point)
	term := new(btcec.JacobianPoint)
	c.Negate()
	btcec.ScalarMultNonConst(c, secret_commitment_point, term)
	// g^\mu_i
	term1 := new(btcec.JacobianPoint)
	btcec.ScalarBaseMultNonConst(s, term1)
	// R_i = g^\mu_i * A_i0^-c
	btcec.AddNonConst(term1, term, R)

	// Fail if R is the point at infinity
	is_infinity := false
	if (R.X.IsZero() && R.Y.IsZero()) || R.Z.IsZero() {
		is_infinity = true
	}
	assert.False(p.suite.T, is_infinity, "verify frost secret proof: R is the point at infinity")

	// R_Y cannot be odd
	R.ToAffine()
	assert.False(p.suite.T, R.Y.IsOdd(), "verify frost secret proof: R.Y is odd")

	// verify R point equals provided R_X
	assert.Equal(p.suite.T, &R.X, R_x, "verify frost secret proof: R.X does not match provided R_X")
}

// calculating f(i)
// calculate secret shares can be parallelized
func (p *FrostParticipant) CalculateSecretShares() {
	p.secretShares = make([]*btcec.ModNScalar, p.N)
	for j := int64(0); j < p.N; j++ {
		// evaluate the secret polynomial at the participant index
		participant_scalar := new(btcec.ModNScalar).SetInt(uint32(j + 1))
		// secret shares as f(x)
		shares := p.suite.EvaluatePolynomial(p.secretPolynomial, participant_scalar)
		p.updateSecretShares(j+1, shares)
	}
}

func (p *FrostParticipant) AllSecretShares() []*btcec.ModNScalar {
	return p.secretShares
}

func (p *FrostParticipant) GetSecretShares(position int64) *btcec.ModNScalar {
	return p.secretShares[position-1]
}

func (p *FrostParticipant) updateSecretShares(posi int64, val *btcec.ModNScalar) {
	// p.secretSharesMutex.Lock()
	// defer p.secretSharesMutex.Unlock()
	p.secretShares[posi-1] = val
}

// verify secret shares
func (p *FrostParticipant) VerifyPublicSecretShares(secretShares *btcec.ModNScalar, which_participant_poly int64, posi uint32) {
	posi_scalar := new(btcec.ModNScalar).SetInt(posi)
	polynomialCommitments := p.PolynomialCommitments[which_participant_poly]

	// calculate A(i) = g^f(i)
	expected_a := new(btcec.JacobianPoint)
	btcec.ScalarBaseMultNonConst(secretShares, expected_a)

	// calculate prod(A_k^i^k)
	i_power := new(btcec.ModNScalar)
	i_power.SetInt(1)
	calculated_a := new(btcec.JacobianPoint)
	for i := 0; i < len(polynomialCommitments); i++ {
		term := new(btcec.JacobianPoint)
		polynomialCommitments[i].AsJacobian(term)
		// calculate term = A_k^i^k = g^(a_k*i^k)
		btcec.ScalarMultNonConst(i_power, term, term)
		term.ToAffine()
		// calculate prod(A_k^i^k)
		btcec.AddNonConst(calculated_a, term, calculated_a)
		i_power.Mul(posi_scalar)
	}

	calculated_a.ToAffine()
	expected_a.ToAffine()

	// there can be even and odd Y coordinate
	// should I check for a specific Y coordinate?

	// check if the calculated commitment is equal to the expected commitment
	assert.Equal(p.suite.T, expected_a.X, calculated_a.X)
}

// verify batch public secret shares for a participant secret shares
//
// expensive operation
func (p *FrostParticipant) VerifyBatchPublicSecretShares(secret_shares map[int64]*btcec.ModNScalar, posi uint32) {
	var wg sync.WaitGroup

	// calculate expected A_i for all parties
	// make(map[int64]*btcec.JacobianPoint)
	// s_ji = f_j(i)
	all_expected_A := make(map[int64]*btcec.JacobianPoint)
	for index, shares := range secret_shares {
		expected_A := new(btcec.JacobianPoint)
		btcec.ScalarBaseMultNonConst(shares, expected_A)
		expected_A.ToAffine()
		all_expected_A[index] = expected_A
	}

	// calculate map of i^k for this participant
	time_now := time.Now()
	posi_scalar := new(btcec.ModNScalar).SetInt(posi)
	i_power_arr := make([]*btcec.ModNScalar, p.Threshold+1)
	i_power := new(btcec.ModNScalar)
	i_power.SetInt(1)
	for i := int64(0); i <= p.Threshold; i++ {
		i_power_arr[i] = new(btcec.ModNScalar).Set(i_power)
		i_power.Mul(posi_scalar)
	}
	p.logger.Printf("calculate i^k time: %v\n", time.Since(time_now))

	// calculate map of A_k^i^k for all parties
	// make(map[int64][]*btcec.JacobianPoint)
	time_now = time.Now()
	all_term := sync.Map{}
	for posi, poly_commitments := range p.PolynomialCommitments {
		wg.Add(1)
		go func(posi int64, poly_commitments []*btcec.PublicKey) {
			term_arr := make([]*secp.JacobianPoint, p.Threshold+1)
			var wg1 sync.WaitGroup
			for i := int64(0); i <= p.Threshold; i++ {
				wg1.Add(1)
				go func(i int64) {
					term := new(btcec.JacobianPoint)
					poly_commitments[i].AsJacobian(term)
					btcec.ScalarMultNonConst(i_power_arr[i], term, term)
					term.ToAffine()
					term_arr[i] = term
					wg1.Done()
				}(i)
			}
			wg1.Wait()
			all_term.Store(posi, term_arr)
			wg.Done()
		}(posi, poly_commitments)
	}
	wg.Wait()
	p.logger.Printf("calculate A_k^i^k time: %v\n", time.Since(time_now))

	// calculate prod(A_k^i^k) for all parties
	// then verify against expected values
	time_now = time.Now()
	all_term.Range(func(key any, value any) bool {
		index := key.(int64)
		term := value.([]*btcec.JacobianPoint)
		wg.Add(1)
		go func(index int64, term []*btcec.JacobianPoint) {
			calculated_A := new(btcec.JacobianPoint)
			for _, val := range term {
				btcec.AddNonConst(calculated_A, val, calculated_A)
			}
			calculated_A.ToAffine()
			expected_A := all_expected_A[index]
			assert.Equal(p.suite.T, expected_A, calculated_A)
			wg.Done()
		}(index, term)

		return true
	})
	wg.Wait()
	p.logger.Printf("verify batch secret shares time: %v\n", time.Since(time_now))
}

func (p *FrostParticipant) CalculateInternalPublicSigningShares(signingShares *btcec.ModNScalar, posi int64) *btcec.PublicKey {
	signingPoint := new(btcec.JacobianPoint)
	btcec.ScalarBaseMultNonConst(signingShares, signingPoint)
	signingPoint.ToAffine()

	p.PublicSigningShares[posi] = btcec.NewPublicKey(&signingPoint.X, &signingPoint.Y)

	return p.PublicSigningShares[posi]
}

// calculate Y_i from other participant secret commitments
//
// n_k: total number of keys
//
// n_p: total number of parties
//
// t: threshold
//
// f_m(x), m \in {1, \ldots, n_p}
//
// recall that Y_i = g^s_i, i \in {1, \ldots, n_k}
//
// recall that A_{mj} = g^{a_{mj}}, j \in {1, \ldots, t}
//
// s_i = \sum_{m=1}^{n_p} f_m(i)
//
// thus, Y_i = g^(\sum_{m=1}^{n_p} f_m(i)) = \prod_{m=1}^{n_p} g^{f_m(i)}
//
// Y_i = \prod_{m=1}^{n_p} g^{\sum_{j=0}^{t} a_mj * i^j}
//
// Y_i = \prod_{m=1}^{n_p} \prod_{j=0}^{t} g^{a_mj * i^j}
//
// Y_i = \prod_{m=1}^{n_p} \prod_{j=0}^{t} A_mj^i^j
//
// intense computation: 0(n*m)
func (p *FrostParticipant) CalculatePublicSigningShares(party_num, posi int64) *btcec.PublicKey {
	posi_scalar := new(btcec.ModNScalar)
	posi_scalar.SetInt(uint32(posi))

	Y := new(btcec.JacobianPoint)
	for i := int64(1); i <= party_num; i++ {
		i_power_map := make([]*btcec.ModNScalar, p.Threshold+1)
		i_power := new(btcec.ModNScalar)
		i_power.SetInt(1)
		for j := int64(0); j <= p.Threshold; j++ {
			i_power_map[j] = new(btcec.ModNScalar).Set(i_power)
			i_power.Mul(posi_scalar)
		}

		// parallel computation
		// \prod_{j=0}^{t} A_mj^i^j
		term_1_map := make([]*btcec.JacobianPoint, p.Threshold+1)
		var wg sync.WaitGroup
		for j := int64(0); j <= p.Threshold; j++ {
			wg.Add(1)
			go func(j int64) {
				// A_mj
				A_ij := new(btcec.JacobianPoint)
				p.PolynomialCommitments[i][j].AsJacobian(A_ij)

				// calculate A_mj^i^j
				term1 := new(btcec.JacobianPoint)
				btcec.ScalarMultNonConst(i_power_map[j], A_ij, term1)

				term_1_map[j] = term1

				wg.Done()
			}(j)
		}
		wg.Wait()

		term := new(btcec.JacobianPoint)
		for j := int64(0); j <= p.Threshold; j++ {
			btcec.AddNonConst(term, term_1_map[j], term)
		}

		btcec.AddNonConst(Y, term, Y)
	}
	Y.ToAffine()

	p.PublicSigningShares[posi] = btcec.NewPublicKey(&Y.X, &Y.Y)

	return p.PublicSigningShares[posi]
}

func (p *FrostParticipant) CalculateGroupPublicKey(party_num int64) *btcec.PublicKey {
	Y := new(btcec.JacobianPoint)
	for i := int64(1); i <= party_num; i++ {
		A_0 := new(btcec.JacobianPoint)
		p.PolynomialCommitments[i][0].AsJacobian(A_0)
		btcec.AddNonConst(Y, A_0, Y)
	}
	Y.ToAffine()

	p.GroupPublicKey = btcec.NewPublicKey(&Y.X, &Y.Y)

	return p.GroupPublicKey
}

func (p *FrostParticipant) GenerateSigningNonces(signing_time int64) [][2]*btcec.PublicKey {
	p.nonces = make([][2]*btcec.ModNScalar, signing_time)
	p.NonceCommitments = make([][2]*btcec.PublicKey, signing_time)
	for i := int64(0); i < signing_time; i++ {
		// generate nonces (d, e) for each signing
		// for pi = 1 number of pairs
		d_seed := p.suite.Generate32BSeed()
		e_seed := p.suite.Generate32BSeed()

		d := new(btcec.ModNScalar)
		d.SetBytes(&d_seed)
		D := new(btcec.JacobianPoint)
		btcec.ScalarBaseMultNonConst(d, D)

		e := new(btcec.ModNScalar)
		e.SetBytes(&e_seed)
		E := new(btcec.JacobianPoint)
		btcec.ScalarBaseMultNonConst(e, E)

		// normalize Z before shipping off (D, E) to other participants
		D.ToAffine()
		E.ToAffine()

		p.nonces[i] = [2]*btcec.ModNScalar{d, e}
		D_Pub := btcec.NewPublicKey(&D.X, &D.Y)
		E_Pub := btcec.NewPublicKey(&E.X, &E.Y)
		p.NonceCommitments[i] = [2]*btcec.PublicKey{D_Pub, E_Pub}
	}

	return p.NonceCommitments
}

// with provided public nonces from other participants, calculate the aggregated public nonce commitments
// R_i = D_i * E_i ^ p_i
// p_i = H(i, m, B)
// B = {D_1, E_1, ..., D_t, E_t}
// where B is the set of public nonces from t participants
// and m is the message to be signed
// and i is the participant's position
//
// honest would be a list of exact position starting from 1
func (p *FrostParticipant) CalculatePublicNonceCommitments(signing_index int64, honest []int64, message_hash [32]byte, public_nonces map[int64][2]*btcec.PublicKey) map[int64]*btcec.PublicKey {
	// calculate p_i for each honest participants
	p_data := make([]byte, 0)
	p_data = append(p_data, message_hash[:]...)
	for _, j := range honest {
		D := new(btcec.JacobianPoint)
		public_nonces[j][0].AsJacobian(D)
		E := new(btcec.JacobianPoint)
		public_nonces[j][1].AsJacobian(E)

		p_data = append(p_data, D.X.Bytes()[:]...)
		p_data = append(p_data, E.X.Bytes()[:]...)
	}

	p_list := make(map[int64]*btcec.ModNScalar)
	for _, i := range honest {
		p_i_data := append([]byte{byte(i)}, p_data...)
		p := chainhash.HashB(p_i_data)
		p_scalar := new(btcec.ModNScalar)
		p_scalar.SetByteSlice(p)

		p_list[i] = p_scalar
	}

	// calculate R and R_i
	nonce_commitments := make(map[int64]*btcec.PublicKey)
	aggrNonceCommitment := new(btcec.JacobianPoint)

	for _, i := range honest {
		D_i := new(btcec.JacobianPoint)
		public_nonces[i][0].AsJacobian(D_i)
		E_i := new(btcec.JacobianPoint)
		public_nonces[i][1].AsJacobian(E_i)

		// E_i ^ p_i
		term := new(btcec.JacobianPoint)
		btcec.ScalarMultNonConst(p_list[i], E_i, term)
		// R_i = D_i * E_i ^ p_i
		R_i := new(btcec.JacobianPoint)
		btcec.AddNonConst(D_i, term, R_i)
		R_i.ToAffine()

		nonce_commitments[i] = btcec.NewPublicKey(&R_i.X, &R_i.Y)
		btcec.AddNonConst(aggrNonceCommitment, R_i, aggrNonceCommitment)
	}
	aggrNonceCommitment.ToAffine()
	p.AggrNonceCommitment[signing_index] = aggrNonceCommitment

	return nonce_commitments
}

// construct z_i = d_i + e_i * p_i + \lambda_i * s_i * c
// \lambda_i is the Lagrange coefficient for the participant i over the honest participants
// s_i is the long-term secret share of participant i
// c = H(R, Y, m)
// TODO: have not checked for even or odd Y - coordinates
func (p *FrostParticipant) PartialSign(position, signing_index int64, honest_party []int64, message_hash [32]byte, public_nonces map[int64][2]*btcec.PublicKey, signing_shares *btcec.ModNScalar) *schnorr.Signature {
	// calculate c
	commitment_data := make([]byte, 0)
	commitment_data = append(commitment_data, p.AggrNonceCommitment[signing_index].X.Bytes()[:]...)
	commitment_data = append(commitment_data, schnorr.SerializePubKey(p.GroupPublicKey)...)
	commitment_data = append(commitment_data, message_hash[:]...)
	commitment_hash := chainhash.TaggedHash(chainhash.TagBIP0340Challenge, commitment_data)
	c := new(btcec.ModNScalar)
	c.SetByteSlice(commitment_hash[:])

	// calculate p_i
	p_i_data := make([]byte, 0)
	p_i_data = append(p_i_data, byte(position))
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
	d_i := new(btcec.ModNScalar).Set(p.nonces[signing_index][0])
	e_i := new(btcec.ModNScalar).Set(p.nonces[signing_index][1])
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
	if p.AggrNonceCommitment[signing_index].Y.IsOdd() {
		d_i.Negate()
		e_i.Negate()
	}

	s_i := new(btcec.ModNScalar).Set(signing_shares)
	if p.GroupPublicKey.SerializeCompressed()[0] == secp.PubKeyFormatCompressedOdd {
		s_i.Negate()
	}

	// calculate larange coefficient
	lamba := p.suite.CalculateLagrangeCoeff(position, honest_party)
	// e_i * p_i
	term = new(btcec.ModNScalar).Mul2(e_i, p_i_scalar)
	// d_i + e_i * p_i
	term1 = new(btcec.ModNScalar).Add2(d_i, term)
	// \lambda_i * s_i * c
	term2 := new(btcec.ModNScalar).Mul2(lamba, s_i).Mul(c)
	// d_i + e_i * p_i + \lambda_i * s_i * c
	z_i := new(btcec.ModNScalar).Add2(term1, term2)

	sig := schnorr.NewSignature(&R_i.X, z_i)

	return sig
}

// construct z_i = d_i + e_i * p_i + \sum_{K_i} \lambda_{ik} * s_{ik} * c, K_i is the threshold set of honest keys of participant i
// \lambda_i is the Lagrange coefficient for the participant i over the honest participants
// s_i is the long-term secret share of participant i
// c = H(R, Y, m)
// TODO: have not checked for even or odd Y - coordinates
//
// a different variant of partial sign for wsts
func (p *FrostParticipant) WeightedPartialSign(position, signing_index int64, honest_party, honest_keys []int64, message_hash [32]byte, public_nonces map[int64][2]*btcec.PublicKey, signing_shares map[int64]*btcec.ModNScalar) *schnorr.Signature {
	// calculate c
	commitment_data := make([]byte, 0)
	commitment_data = append(commitment_data, p.AggrNonceCommitment[signing_index].X.Bytes()[:]...)
	commitment_data = append(commitment_data, schnorr.SerializePubKey(p.GroupPublicKey)...)
	commitment_data = append(commitment_data, message_hash[:]...)
	commitment_hash := chainhash.TaggedHash(chainhash.TagBIP0340Challenge, commitment_data)
	c := new(btcec.ModNScalar)
	c.SetByteSlice(commitment_hash[:])

	p.logger.Printf("sign c: %v, group pubkey: %v, aggr nonce commitments: %v\n", c, p.GroupPublicKey, p.AggrNonceCommitment[signing_index].X)

	// calculate p_i
	p_i_data := make([]byte, 0)
	p_i_data = append(p_i_data, byte(position))
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
	d_i := new(btcec.ModNScalar).Set(p.nonces[signing_index][0])
	e_i := new(btcec.ModNScalar).Set(p.nonces[signing_index][1])
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
	if p.AggrNonceCommitment[signing_index].Y.IsOdd() {
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
	for key_index, shares := range signing_shares {
		s_i := new(btcec.ModNScalar).Set(shares)
		if p.GroupPublicKey.SerializeCompressed()[0] == secp.PubKeyFormatCompressedOdd {
			s_i.Negate()
		}

		// check shares
		temp := new(btcec.JacobianPoint)
		btcec.ScalarBaseMultNonConst(s_i, temp)
		temp.ToAffine()
		p.logger.Printf("sign key_index %d: signing shares verification %v\n", key_index, temp)

		// calculate larange coefficient
		lamba := p.suite.CalculateLagrangeCoeff(key_index, honest_keys)
		// \lambda_{ik} * s_{ik} * c
		term2 := new(btcec.ModNScalar).Mul2(lamba, s_i).Mul(c)
		// \sum_{K_i} \lambda_{ik} * s_{ik} * c
		term3.Add(term2)
	}
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
func (p *FrostParticipant) WeightedPartialVerification(sig *schnorr.Signature, signing_index, posi int64, message_hash [32]byte, honest_keys []int64, signing_verification_shares map[int64]*btcec.PublicKey) bool {
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
	commitment_data = append(commitment_data, p.AggrNonceCommitment[signing_index].X.Bytes()[:]...)
	commitment_data = append(commitment_data, schnorr.SerializePubKey(p.GroupPublicKey)...)
	commitment_data = append(commitment_data, message_hash[:]...)
	commitment_hash := chainhash.TaggedHash(chainhash.TagBIP0340Challenge, commitment_data)
	c := new(btcec.ModNScalar)
	c.SetByteSlice(commitment_hash[:])

	p.logger.Printf("message_hash: %v\n", message_hash)
	p.logger.Printf("verify c: %v\n", c)

	c.Negate()

	// calculate \prod_{K_i} Y_{ik}^-(\lambda_{ik} * c)
	prod := new(btcec.JacobianPoint)
	for key_index, shares := range signing_verification_shares {
		Y_i := new(btcec.JacobianPoint)
		shares.AsJacobian(Y_i)
		if p.GroupPublicKey.SerializeCompressed()[0] == secp.PubKeyFormatCompressedOdd {
			Y_i.Y.Negate(1)
			Y_i.Y.Normalize()
		}

		// check shares
		Y_i.ToAffine()
		p.logger.Printf("verify key_index %d: signing verification shares %v\n", key_index, Y_i)

		// calculate \lambda_{ik} * -c
		term := new(btcec.ModNScalar)
		lambda := p.suite.CalculateLagrangeCoeff(key_index, honest_keys)
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
	assert.False(p.suite.T, is_infinity, "verify partial sig proof: R is the point at infinity")
	if is_infinity {
		return false
	}

	R.ToAffine()

	// verify R point equals provided R_X
	assert.Equal(p.suite.T, &R.X, R_X, "verify partial sig proof: R.X does not match provided R_X")
	return R.X.Equals(R_X)
}
