package testhelper

import (
	"log"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
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

// FrostParticipant multiple signing usages are meant to sign multiple messages with this Frost setup
type FrostParticipant struct {
	suite  *TestSuite
	logger *log.Logger

	N         int
	Threshold int
	Position  int

	secretSharesMutex sync.Mutex

	secretPolynomial []*btcec.ModNScalar
	secretShares     []*btcec.ModNScalar
	// nonce commitments for multiples signing usages
	nonces [][2]*btcec.ModNScalar

	PolynomialCommitment []*btcec.PublicKey

	PolynomialCommitments [][]*btcec.PublicKey
	PublicSigningShares   map[int]*btcec.PublicKey
	GroupPublicKey        *btcec.PublicKey
	// contains the nonce commitments for multiple signing usages
	NonceCommitments [][2]*btcec.PublicKey
	// contains the aggregated nonce commitments for multiple signing usages
	AggrNonceCommitment map[int]*btcec.JacobianPoint
}

func NewFrostParticipant(suite *TestSuite, logger *log.Logger, n, threshold, posi int, secret *btcec.ModNScalar) *FrostParticipant {
	// generate secret polynomial
	secretPolynomial := suite.GeneratePolynomial(threshold)
	if secret != nil {
		secretPolynomial[0] = secret
	}
	polynomialCommitment := generatePedersenCommitments(secretPolynomial)

	frost := &FrostParticipant{
		suite:                suite,
		logger:               logger,
		N:                    n,
		Threshold:            threshold,
		Position:             posi,
		PolynomialCommitment: polynomialCommitment,
		secretPolynomial:     secretPolynomial,
		//PolynomialCommitments: make(map[int][]*btcec.PublicKey),
		PublicSigningShares: make(map[int]*btcec.PublicKey),
		AggrNonceCommitment: make(map[int]*secp.JacobianPoint),
	}

	// generate public polynomial commitments
	//frost.PolynomialCommitments[posi] = frost.generatePedersenCommitments()
	return frost
}

// calculate A(k) = g^a_k
func generatePedersenCommitments(polynomial []*btcec.ModNScalar) []*btcec.PublicKey {
	commitments := make([]*btcec.PublicKey, len(polynomial))
	for i := 0; i < len(polynomial); i++ {
		// g^a_k
		point := new(btcec.JacobianPoint)
		btcec.ScalarBaseMultNonConst(polynomial[i], point)
		point.ToAffine()
		commitments[i] = btcec.NewPublicKey(&point.X, &point.Y)
	}
	return commitments
}

//
//func (p *FrostParticipant) UpdatePolynomialCommitments(posi int, commitments []*btcec.PublicKey) {
//	p.PolynomialCommitments[posi] = commitments
//}

// CalculateSecretProofsChallenge calculating secret proofs challenge
// c = H(i, stamp, A_i, R_i)
func (p *FrostParticipant) CalculateSecretProofsChallenge(context_hash [32]byte, R_x *btcec.FieldVal, position int, secretCommitments *btcec.PublicKey) *btcec.ModNScalar {
	// c = H(i, stamp, A_i, R_i)
	commitmentData := make([]byte, 0)
	commitmentData = append(commitmentData, byte(position))
	commitmentData = append(commitmentData, context_hash[:]...)
	commitmentData = append(commitmentData, schnorr.SerializePubKey(secretCommitments)...)
	commitmentData = append(commitmentData, R_x.Bytes()[:]...)

	commitmentHash := chainhash.TaggedHash(TagFROSTChallenge, commitmentData)
	c := new(btcec.ModNScalar)
	c.SetByteSlice(commitmentHash[:])

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
	secretCommitmentBytes := p.PolynomialCommitment[0].SerializeCompressed()
	if secretCommitmentBytes[0] == secp.PubKeyFormatCompressedOdd {
		secret.Negate()
	}

	c := p.CalculateSecretProofsChallenge(context_hash, &R.X, p.Position, p.PolynomialCommitment[0])

	sScalar := new(btcec.ModNScalar).Mul2(secret, c).Add(k)
	sig := schnorr.NewSignature(&R.X, sScalar)

	return sig
}

func (p *FrostParticipant) VerifySecretProofs(contextHash [32]byte, secretProof *schnorr.Signature, position int, secretCommitments *btcec.PublicKey) {
	// retrive (R, s) from secret Schnorr proof
	secretProofBytes := secretProof.Serialize()
	RBytes := secretProofBytes[0:32]
	RX := new(btcec.FieldVal)
	RX.SetByteSlice(RBytes)
	sBytes := secretProofBytes[32:64]
	s := new(btcec.ModNScalar)
	s.SetByteSlice(sBytes)

	c := p.CalculateSecretProofsChallenge(contextHash, RX, position, secretCommitments)

	// making even the public key Y coordinate
	secretCommitmentBytes := schnorr.SerializePubKey(secretCommitments)
	secretCommitmentPubkey, err := schnorr.ParsePubKey(secretCommitmentBytes)
	assert.Nil(p.suite.T, err)

	R := new(btcec.JacobianPoint)
	// A_i0^-c
	secretCommitmentPoint := new(btcec.JacobianPoint)
	secretCommitmentPubkey.AsJacobian(secretCommitmentPoint)
	term := new(btcec.JacobianPoint)
	c.Negate()
	btcec.ScalarMultNonConst(c, secretCommitmentPoint, term)
	// g^\mu_i
	term1 := new(btcec.JacobianPoint)
	btcec.ScalarBaseMultNonConst(s, term1)
	// R_i = g^\mu_i * A_i0^-c
	btcec.AddNonConst(term1, term, R)

	// Fail if R is the point at infinity
	isInfinity := false
	if (R.X.IsZero() && R.Y.IsZero()) || R.Z.IsZero() {
		isInfinity = true
	}
	assert.False(p.suite.T, isInfinity, "verify frost secret proof: R is the point at infinity")

	// R_Y cannot be odd
	R.ToAffine()
	assert.False(p.suite.T, R.Y.IsOdd(), "verify frost secret proof: R.Y is odd")

	// verify R point equals provided R_X
	assert.Equal(p.suite.T, &R.X, RX, "verify frost secret proof: R.X does not match provided R_X")
}

// CalculateSecretShares calculating f(i)
// calculate secret shares can be parallelized
func (p *FrostParticipant) CalculateSecretShares() {
	p.secretShares = make([]*btcec.ModNScalar, p.N)
	for j := 0; j < p.N; j++ {
		// evaluate the secret polynomial at the participant index
		participantScalar := new(btcec.ModNScalar).SetInt(uint32(j + 1))
		// secret shares as f(x)
		shares := p.suite.EvaluatePolynomial(p.secretPolynomial, participantScalar)
		p.updateSecretShares(j+1, shares)
	}
}

func (p *FrostParticipant) AllSecretShares() []*btcec.ModNScalar {
	return p.secretShares
}

func (p *FrostParticipant) GetSecretShares(position int) *btcec.ModNScalar {
	return p.secretShares[position-1]
}

func (p *FrostParticipant) updateSecretShares(posi int, val *btcec.ModNScalar) {
	// p.secretSharesMutex.Lock()
	// defer p.secretSharesMutex.Unlock()
	p.secretShares[posi-1] = val
}

// VerifyPublicSecretShares verify secret shares
func (p *FrostParticipant) VerifyPublicSecretShares(secretShares *btcec.ModNScalar, whichParticipantPoly int) {
	posiScalar := new(btcec.ModNScalar).SetInt(uint32(p.Position))
	polynomialCommitments := p.PolynomialCommitments[whichParticipantPoly]

	// calculate A(i) = g^f(i)
	expectedA := new(btcec.JacobianPoint)
	btcec.ScalarBaseMultNonConst(secretShares, expectedA)

	// calculate prod(A_k^i^k)
	iPower := new(btcec.ModNScalar)
	iPower.SetInt(1)
	calculatedA := new(btcec.JacobianPoint)
	for i := 0; i < len(polynomialCommitments); i++ {
		term := new(btcec.JacobianPoint)
		polynomialCommitments[i].AsJacobian(term)
		// calculate term = A_k^i^k = g^(a_k*i^k)
		btcec.ScalarMultNonConst(iPower, term, term)
		// calculate prod(A_k^i^k)
		btcec.AddNonConst(calculatedA, term, calculatedA)
		iPower.Mul(posiScalar)
	}

	calculatedA.ToAffine()
	expectedA.ToAffine()

	// there can be even and odd Y coordinate
	// should I check for a specific Y coordinate?

	// check if the calculated commitment is equal to the expected commitment
	assert.Equal(p.suite.T, expectedA.X, calculatedA.X)
}

// VerifyBatchPublicSecretShares verify batch public secret shares for a participant secret shares
//
// expensive operation
func (p *FrostParticipant) VerifyBatchPublicSecretShares(secretShares map[int]*btcec.ModNScalar) {
	// calculate expected A_i for all parties
	// make(map[int]*btcec.JacobianPoint)
	// s_ji = f_j(i)
	allExpectedA := make(map[int]*btcec.JacobianPoint)
	for index, shares := range secretShares {
		expectedA := new(btcec.JacobianPoint)
		btcec.ScalarBaseMultNonConst(shares, expectedA)
		expectedA.ToAffine()
		allExpectedA[index] = expectedA
	}

	// calculate map of i^k for this participant
	posiScalar := new(btcec.ModNScalar).SetInt(uint32(p.Position))
	iPowerArr := make([]*btcec.ModNScalar, p.Threshold+1)
	//TODO: can be optimized
	iPower := new(btcec.ModNScalar)
	iPower.SetInt(1)
	for i := 0; i <= p.Threshold; i++ {
		iPowerArr[i] = new(btcec.ModNScalar).Set(iPower)
		iPower.Mul(posiScalar)
	}

	// calculate map of A_k^i^k for all parties
	// make(map[int][]*btcec.JacobianPoint)
	timeNow := time.Now()
	allTerms := sync.Map{}
	var wg sync.WaitGroup
	for i := 1; i < len(p.PolynomialCommitments); i++ {
		wg.Add(1)
		go func(posi int, polyCommitments []*btcec.PublicKey) {
			defer wg.Done()
			termArr := make([]*secp.JacobianPoint, p.Threshold+1)
			for i := 0; i <= p.Threshold; i++ {
				term := new(btcec.JacobianPoint)
				polyCommitments[i].AsJacobian(term)
				btcec.ScalarMultNonConst(iPowerArr[i], term, term)
				//term.ToAffine() this is redundant and expensive, check the method comments
				termArr[i] = term
			}
			allTerms.Store(posi, termArr)
		}(i, p.PolynomialCommitments[i])
	}
	wg.Wait()
	p.logger.Printf("calculate A_k^i^k time: %v\n", time.Since(timeNow))

	// calculate prod(A_k^i^k) for all parties
	// then verify against expected values
	timeNow = time.Now()
	// TODO: fix allTerms type
	allTerms.Range(func(key any, value any) bool {
		index := key.(int)
		terms := value.([]*btcec.JacobianPoint)
		wg.Add(1)
		go func(index int, terms []*btcec.JacobianPoint) {
			defer wg.Done()
			// Sum all the terms
			sum := new(btcec.JacobianPoint)
			for _, term := range terms {
				btcec.AddNonConst(sum, term, sum)
			}
			sum.ToAffine()
			expectedA := allExpectedA[index]
			assert.Equal(p.suite.T, expectedA, sum)
		}(index, terms)

		return true
	})
	wg.Wait()

	p.logger.Printf("verify batch secret shares time: %v\n", time.Since(timeNow))
}

func (p *FrostParticipant) CalculateInternalPublicSigningShares(signingShares *btcec.ModNScalar) *btcec.PublicKey {
	signingPoint := new(btcec.JacobianPoint)
	btcec.ScalarBaseMultNonConst(signingShares, signingPoint)
	signingPoint.ToAffine()

	p.PublicSigningShares[p.Position] = btcec.NewPublicKey(&signingPoint.X, &signingPoint.Y)

	return p.PublicSigningShares[p.Position]
}

// CalculatePublicSigningShares calculate Y_i from other participant secret commitments
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
func (p *FrostParticipant) CalculatePublicSigningShares(aggregateCommitments []*btcec.JacobianPoint, posi int) *btcec.PublicKey {
	posiScalar := new(btcec.ModNScalar)
	posiScalar.SetInt(uint32(posi))

	Y := new(btcec.JacobianPoint)

	// cacheable
	iPowerMap := make([]*btcec.ModNScalar, p.Threshold+1)
	iPower := new(btcec.ModNScalar)
	iPower.SetInt(1)
	for j := 0; j <= p.Threshold; j++ {
		iPowerMap[j] = new(btcec.ModNScalar).Set(iPower)
		iPower.Mul(posiScalar)
	}

	for j := 0; j <= p.Threshold; j++ {
		agg := new(btcec.JacobianPoint)
		btcec.ScalarMultNonConst(iPowerMap[j], aggregateCommitments[j], agg)
		btcec.AddNonConst(Y, agg, Y)
	}
	Y.ToAffine()

	p.PublicSigningShares[posi] = btcec.NewPublicKey(&Y.X, &Y.Y)

	return p.PublicSigningShares[posi]
}

func (p *FrostParticipant) CalculateGroupPublicKey(party_num int) *btcec.PublicKey {
	Y := new(btcec.JacobianPoint)
	for i := 1; i <= party_num; i++ {
		A_0 := new(btcec.JacobianPoint)
		p.PolynomialCommitments[i][0].AsJacobian(A_0)
		btcec.AddNonConst(Y, A_0, Y)
	}
	Y.ToAffine()

	p.GroupPublicKey = btcec.NewPublicKey(&Y.X, &Y.Y)

	return p.GroupPublicKey
}

func (p *FrostParticipant) GenerateSigningNonces(signing_time int) [][2]*btcec.PublicKey {
	p.nonces = make([][2]*btcec.ModNScalar, signing_time)
	p.NonceCommitments = make([][2]*btcec.PublicKey, signing_time)
	for i := 0; i < signing_time; i++ {
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

// CalculatePublicNonceCommitments with provided public nonces from other participants, calculate the aggregated public nonce commitments
// R_i = D_i * E_i ^ p_i
// p_i = H(i, m, B)
// B = {D_1, E_1, ..., D_t, E_t}
// where B is the set of public nonces from t participants
// and m is the message to be signed
// and i is the participant's position
//
// honest would be a list of exact position starting from 1
func (p *FrostParticipant) CalculatePublicNonceCommitments(signing_index int, honest []int, message_hash [32]byte, public_nonces map[int][2]*btcec.PublicKey) map[int]*btcec.PublicKey {
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

	p_list := make(map[int]*btcec.ModNScalar)
	for _, i := range honest {
		p_i_data := append([]byte{byte(i)}, p_data...)
		p := chainhash.HashB(p_i_data)
		p_scalar := new(btcec.ModNScalar)
		p_scalar.SetByteSlice(p)

		p_list[i] = p_scalar
	}

	// calculate R and R_i
	nonce_commitments := make(map[int]*btcec.PublicKey)
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

// PartialSign construct z_i = d_i + e_i * p_i + \lambda_i * s_i * c
// \lambda_i is the Lagrange coefficient for the participant i over the honest participants
// s_i is the long-term secret share of participant i
// c = H(R, Y, m)
// TODO: have not checked for even or odd Y - coordinates
func (p *FrostParticipant) PartialSign(position, signing_index int, honest_party []int, message_hash [32]byte, public_nonces map[int][2]*btcec.PublicKey, signing_shares *btcec.ModNScalar) *schnorr.Signature {
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

// WeightedPartialSign construct z_i = d_i + e_i * p_i + \sum_{K_i} \lambda_{ik} * s_{ik} * c, K_i is the threshold set of honest keys of participant i
// \lambda_i is the Lagrange coefficient for the participant i over the honest participants
// s_i is the long-term secret share of participant i
// c = H(R, Y, m)
// TODO: have not checked for even or odd Y - coordinates
//
// a different variant of partial sign for wsts
func (p *FrostParticipant) WeightedPartialSign(position, signing_index int, honest_party, honest_keys []int, message_hash [32]byte, public_nonces map[int][2]*btcec.PublicKey, signing_shares map[int]*btcec.ModNScalar) *schnorr.Signature {
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

// WeightedPartialVerification verifying the partial signature from each honest participant
// recall that: z_i = d_i + e_i * p_i + \sum_{K_i} \lambda_{ik} * s_{ik} * c
// thus, g^z_i = R_i * g^(\sum_{K_i} \lambda_{ik} * s_{ik} * c) = R_i * \prod_{K_i} Y_{ik}^(\lambda_{ik} * c)
// thus, R_i = g^z_i * \prod_{K_i} Y_{ik}^-(\lambda_{ik} * c)
//
// a different variant of partial sign for wsts
func (p *FrostParticipant) WeightedPartialVerification(sig *schnorr.Signature, signing_index, posi int, message_hash [32]byte, honest_keys []int, signing_verification_shares map[int]*btcec.PublicKey) bool {
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
