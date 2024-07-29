package testhelper

import (
	"sync"

	btcec "github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/assert"
)

// seem like FROST will be hevily used as a bitcoin building block
// thus, it will be re - used in many tests

var (
	TagFROSTChallenge = []byte("FROST/challenge")
)

type FrostParticipant struct {
	suite *TestSuite

	N        int64
	Theshold int64
	Position int64

	secretSharesMutex sync.Mutex

	secretPolynomial []*btcec.ModNScalar
	secretShares     []*btcec.ModNScalar
	nonces           [][2]*btcec.ModNScalar

	PolynomialCommitments map[int64][]*btcec.PublicKey
	PublicSigningShares   map[int64]*btcec.PublicKey
	GroupPublicKey        *btcec.PublicKey
	NonceCommitments      [][2]*btcec.PublicKey
}

func NewFrostParticipant(suite *TestSuite, n, theshold, posi int64, secret *btcec.ModNScalar) *FrostParticipant {
	frost := &FrostParticipant{
		suite:                 suite,
		N:                     n,
		Theshold:              theshold,
		Position:              posi,
		PolynomialCommitments: make(map[int64][]*btcec.PublicKey),
		PublicSigningShares:   make(map[int64]*btcec.PublicKey),
	}

	// generate secret polynomial
	frost.secretPolynomial = suite.GeneratePolynomial(theshold)
	if secret != nil {
		frost.secretPolynomial[0] = secret
	}
	// generate public polynomial commitments
	frost.PolynomialCommitments[posi] = frost.generatePedersenCommitments()

	return frost
}

// calculate A(k) = g^a_k
func (p *FrostParticipant) generatePedersenCommitments() []*btcec.PublicKey {
	commitments := make([]*btcec.PublicKey, p.Theshold+1)
	for i := int64(0); i <= p.Theshold; i++ {
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
func (p *FrostParticipant) VerifyPublicSecretShares(secretShares *btcec.ModNScalar, polynomialCommitments []*btcec.PublicKey, posi uint32) {
	posi_scalar := new(btcec.ModNScalar).SetInt(posi)

	// calculate A(i) = g^f(i)
	expected_a := new(btcec.JacobianPoint)
	btcec.ScalarBaseMultNonConst(secretShares, expected_a)

	// calculate prod(A_k^i^k)
	product := new(btcec.ModNScalar)
	product.SetInt(1)
	i_power := new(btcec.ModNScalar)
	i_power.SetInt(1)
	calculated_a := new(btcec.JacobianPoint)
	for i := 0; i < len(polynomialCommitments); i++ {
		term := new(btcec.JacobianPoint)
		polynomialCommitments[i].AsJacobian(term)
		// calculate term = A_k^i^k = g^(a_k*i^k)
		btcec.ScalarMultNonConst(i_power, term, term)
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

func (p *FrostParticipant) CalculateInternalPublicSigningShares(signingShares *btcec.ModNScalar, posi int64) *btcec.PublicKey {
	signingPoint := new(btcec.JacobianPoint)
	btcec.ScalarBaseMultNonConst(signingShares, signingPoint)
	signingPoint.ToAffine()

	p.PublicSigningShares[posi] = btcec.NewPublicKey(&signingPoint.X, &signingPoint.Y)

	return p.PublicSigningShares[posi]
}

// calculate Y_i from other participant secret commitments
// n_k: total number of keys
// n_p: total number of parties
// t: threshold
// f_m(x), m \in {1, \ldots, n_p}
// recall that Y_i = g^s_i, i \in {1, \ldots, n_k}
// recall that A_{mj} = g^{a_{mj}}, j \in {1, \ldots, t}
// s_i = \sum_{m=1}^{n_p} f_m(i)
// thus, Y_i = g^(\sum_{m=1}^{n_p} f_m(i)) = \prod_{m=1}^{n_p} g^{f_m(i)}
// Y_i = \prod_{m=1}^{n_p} g^{\sum_{j=0}^{t} a_mj * i^j}
// Y_i = \prod_{m=1}^{n_p} \prod_{j=0}^{t} g^{a_mj * i^j}
// Y_i = \prod_{m=1}^{n_p} \prod_{j=0}^{t} A_mj^i^k
//
// intense computation: 0(n*m)
func (p *FrostParticipant) CalculatePublicSigningShares(party_num, posi int64, secret_commitments map[int64][]*btcec.PublicKey) *btcec.PublicKey {
	posi_scalar := new(btcec.ModNScalar)
	posi_scalar.SetInt(uint32(posi))

	Y := new(btcec.JacobianPoint)
	for i := int64(1); i <= party_num; i++ {
		i_power := new(btcec.ModNScalar)
		i_power.SetInt(1)
		// \prod_{j=0}^{t} A_mj^i^k
		term := new(btcec.JacobianPoint)
		for j := int64(0); j <= p.Theshold; j++ {
			// A_mj
			A_ij := new(btcec.JacobianPoint)
			secret_commitments[i][j].AsJacobian(A_ij)

			// calculate A_mj^i^k
			term1 := new(btcec.JacobianPoint)
			btcec.ScalarMultNonConst(i_power, A_ij, term1)

			btcec.AddNonConst(term, term1, term)

			i_power.Mul(posi_scalar)
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

func (p *FrostParticipant) GenerateSigningNonces(usage_time int64) [][2]*btcec.PublicKey {
	p.nonces = make([][2]*btcec.ModNScalar, usage_time)
	p.NonceCommitments = make([][2]*btcec.PublicKey, usage_time)
	for i := int64(0); i < usage_time; i++ {
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
