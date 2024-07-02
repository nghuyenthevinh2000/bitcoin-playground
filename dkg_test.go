package main

import (
	"crypto/rand"
	"testing"

	btcec "github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/assert"
)

// witness - execution oracle test

var (
	// 7 oracles seed
	oracles = []string{
		"af7ed20e1855c15ac42d3e6998fd8b9e66e56511f70b39d50f0b8a724861d4ee",
		"e57c3400fb99b1913b7d869b110ebada3e84fc0e0ca4bda3849f856b18fc85fa",
		"b571c4fa58c8c42f1db56a6bec88069f8828b58b5b6b18dabc65e8a30f7cc520",
		"45dec5b5e915b25d8a74f1f353e0bcc9965a3019c5fb1a303dad309ce0cf0023",
		"2c3578240978cd66af3186d967f4a1a286aad501df5053bd515a9d9323d25ca9",
		"6990dcdd5c3c50543d9dcbdd53e507a3b1143479043a08f8c1db238c8e31f9cc",
		"6ce7a29477312186ed837ff2831063e76623fe60d971a4378d9a03f45fa47048",
	}
)

type Participant struct {
	Pair         KeyPair
	Secret       *btcec.ModNScalar
	SecretShares map[int]*btcec.ModNScalar
	// the reason for commitment shares here is for it to be multiplied with the secret shares to derive commitments
	// as such, the secret shares cannot be changed without changing the commitment shares
	CommitmentShares map[int]*btcec.ModNScalar
	Commitments      []*btcec.PublicKey
}

// go test -v -run ^TestBasicPedersenDKG$ github.com/nghuyenthevinh2000/bitcoin-playground
// Test the very basic Pedersen Distributed Key Generation (DKG) protocol
// For verication of the shares,
// f(x) = a_0 + a_1*x + a_2*x^2 + ... + a_t*x^t
// h(x) = b_0 + b_1*x + b_2*x^2 + ... + b_t*x^t
// f(i), and h(i) are the secret shares, and commitment shares
// F(x) = g^f(x) = g^(a_0 + a_1*x + a_2*x^2 + ... + a_t*x^t)
// H(x) = g^h(x) = g^(b_0 + b_1*x + b_2*x^2 + ... + b_t*x^t)
// C(i) = g^f(i) * g^h(i) = g^(f(i) + h(i)) -> C(i) = F(i) * G(i)
// C(i) = prod(E_k^i^k), k = [0, t] which is the power of x
// e_k = a_k + b_k -> E_k = g^e_k = g^(a_k + b_k)
// f(i) + g(i) = sum(e_k*i^k), k = [0, t]
//
// For finding secret, we use Larange interpolation to find the secret f(0)
//
// TODO: make this works for randomized participants instead of (1, 2, 3, 4, 5)
//
// NOTICE: there are two kinds of commitments here, please make sure to not confuse them
// 1. commitments of polynomial coefficients: E(k) = g^(a_k + b_k) = g^e_k
// 2. commitments of secret shares: C(i) = g^(f(i) + h(i)) = prod(E(k)^i^k), k = [0, t]
func TestBasicPedersenDKG(t *testing.T) {
	s := TestSuite{}
	s.setupStaticSimNetSuite(t)

	// setup 7 participants
	// threshold = 5
	threshold := 5
	participants := make([]*Participant, len(oracles))
	for i, oracle := range oracles {
		_, pair := s.newKeyPair(oracle)
		participants[i] = &Participant{
			Pair:             pair,
			SecretShares:     make(map[int]*btcec.ModNScalar),
			CommitmentShares: make(map[int]*btcec.ModNScalar),
		}
	}

	// In the Pedersen DKG scheme, each participant generates
	// two polynomials: one for the secret shares and another for the commitments.
	// The commitments polynomial helps in proving that the shares
	// are valid without revealing the actual secret.
	// if each
	for i := range participants {
		participants[i] = s.participantDKG(threshold, len(oracles), participants[i])
	}

	// verify the shares
	for i := 0; i < len(oracles); i++ {
		for k := 0; k < len(oracles); k++ {
			participant_scalar := new(btcec.ModNScalar)
			participant_scalar.SetInt(uint32(k + 1))
			s.verifyPublicShare(participants[i].SecretShares[k], participants[i].CommitmentShares[k], participants[i].Commitments, participant_scalar)
		}
	}

	// participant 1 will then broadcast the shares to all other participants in the network
	// each participant will verify the shares
	// then compute the secret
	for i := 0; i < len(oracles); i++ {
		secret_scalar := s.retrieveSecret(participants[i].SecretShares)
		// verify the secret
		assert.Equal(t, participants[i].Secret, secret_scalar)
	}
}

func (s *TestSuite) participantDKG(threshold, participant_num int, participant *Participant) *Participant {
	secretPolynomial := s.generatePolynomial(threshold - 1)
	commitmentPolynomial := s.generatePolynomial(threshold - 1)
	participant.Commitments = s.generateCommitments(secretPolynomial, commitmentPolynomial)
	participant.Secret = secretPolynomial[0]

	// calculate shares for each participant
	for j := 0; j < participant_num; j++ {
		// evaluate the secret polynomial at the participant index
		participant_scalar := new(btcec.ModNScalar).SetInt(uint32(j + 1))
		// secret shares as f(x)
		participant.SecretShares[j] = s.evaluatePolynomial(secretPolynomial, participant_scalar)
		// commitment shares as g(x)
		participant.CommitmentShares[j] = s.evaluatePolynomial(commitmentPolynomial, participant_scalar)
	}

	// verify internal shares
	for i := 0; i < participant_num; i++ {
		// expected commitment: g^(f(i) + h(i))
		e := new(btcec.ModNScalar).Add2(participant.SecretShares[i], participant.CommitmentShares[i])
		expected_commitment := new(btcec.JacobianPoint)
		btcec.ScalarBaseMultNonConst(e, expected_commitment)

		participant_scalar := new(btcec.ModNScalar)
		participant_scalar.SetInt(uint32(i + 1))

		// calculate sum(a_k*i^k + b_k*i^k), k = [0, t]
		i_power := new(btcec.ModNScalar)
		i_power.SetInt(1)
		sum_scalar := new(btcec.ModNScalar)
		sum_scalar.SetInt(0)
		// interesting this part where I only need to have a threshold number of participants
		for k := 0; k < threshold; k++ {
			// calculate term_1 = a_k*i^k
			term_1 := new(btcec.ModNScalar).Mul2(secretPolynomial[k], i_power)
			// calculate term_2 = b_k*i^k
			term_2 := new(btcec.ModNScalar).Mul2(commitmentPolynomial[k], i_power)
			// calculate term_3 = term_1 + term_2
			term_3 := new(btcec.ModNScalar).Add2(term_1, term_2)

			sum_scalar.Add(term_3)

			// i^k
			i_power.Mul(participant_scalar)
		}

		// verify that both sum is equal
		assert.Equal(s.t, e, sum_scalar, "internal verification: failed sum")

		// calculate prod(E_k^i^k)
		product := new(btcec.JacobianPoint)
		btcec.ScalarBaseMultNonConst(sum_scalar, product)

		// check if the calculated commitment is equal to the expected commitment
		assert.Equal(s.t, expected_commitment.X, product.X, "internal verification of shares failed")
	}

	return participant
}

// a polynomial of degree t-1
// f(x) = a_0 + a_1*x + a_2*x^2 + ... + a_t*x^t
// we store the coefficients in the form of a slice
// each coefficient is generated randomly, this is very much like generating nonces
func (s *TestSuite) generatePolynomial(degree int) []*btcec.ModNScalar {
	polynomial := make([]*btcec.ModNScalar, degree+1)
	// the value a_0 is the secret, others should be able to retrieve the secret
	for i := 0; i <= degree; i++ {
		var coeff btcec.ModNScalar
		int_secp256k1_rand, err := rand.Int(rand.Reader, btcec.S256().N)
		assert.Nil(s.t, err)
		coeff.SetByteSlice(int_secp256k1_rand.Bytes())
		polynomial[i] = &coeff
	}
	return polynomial
}

// calculate E_k = g^(a_k + b_k) = g^e_k
// compute commitment points for each polynomial coefficients
func (s *TestSuite) generateCommitments(secretPoly, commitmentPoly []*btcec.ModNScalar) []*btcec.PublicKey {
	commitments := make([]*btcec.PublicKey, len(secretPoly))
	for i := 0; i < len(secretPoly); i++ {
		// a_k + b_k
		aggr_scalar := new(btcec.ModNScalar).Add2(secretPoly[i], commitmentPoly[i])
		// g^(f(x) + h(x))
		aggr_point := new(btcec.JacobianPoint)
		btcec.ScalarBaseMultNonConst(aggr_scalar, aggr_point)
		aggr_point.ToAffine()
		commitments[i] = btcec.NewPublicKey(&aggr_point.X, &aggr_point.Y)
	}
	return commitments
}

// VSS shares are generated by evaluating the polynomial f(i)
//
// 1. Each participant holds a share of the secret, and the secret
// can be reconstructed only if enough shares are combined.
//
// 2. By distributing shares instead of the actual secret, the scheme
// ensures that no single participant can reconstruct the secret on
// their own. Even if some participants collude, as long as their number
// is below the threshold, the secret remains protected.
// polynomial definition: https://byjus.com/maths/polynomial
func (s *TestSuite) evaluatePolynomial(polynomial []*btcec.ModNScalar, x *btcec.ModNScalar) *btcec.ModNScalar {
	result := new(btcec.ModNScalar)
	result.SetInt(0)
	x_power := new(btcec.ModNScalar)
	x_power.SetInt(1)
	for _, coeff := range polynomial {
		// evaluate the term a_i * x^i
		term := new(btcec.ModNScalar).Mul2(coeff, x_power)
		// add the term to the result
		result.Add(term)
		// raise x to the next power
		x_power.Mul(x)
	}
	return result
}

// each participant can verify share with (f(i), h(i), E)
// prod(E_k^i^k) = g^sum(e_k*i^k), k = [0, t]
func (s *TestSuite) verifyPublicShare(secretShares, commitmentShares *btcec.ModNScalar, commitments []*btcec.PublicKey, participant_scalar *btcec.ModNScalar) {
	// calculate C(i) = g^f(i) * g^h(i) = g^(f(i) + h(i))
	aggr_scalar := new(btcec.ModNScalar).Add2(secretShares, commitmentShares)
	expected_c := new(btcec.JacobianPoint)
	btcec.ScalarBaseMultNonConst(aggr_scalar, expected_c)

	// calculate prod(E_k^i^k)
	product := new(btcec.ModNScalar)
	product.SetInt(1)
	i_power := new(btcec.ModNScalar)
	i_power.SetInt(1)
	calculated_c := new(btcec.JacobianPoint)
	for i := 0; i < len(commitments); i++ {
		term := new(btcec.JacobianPoint)
		e := new(btcec.JacobianPoint)
		commitments[i].AsJacobian(e)
		// calculate term = E_k^i^k = g^(e_k*i^k) = g^(a_k*i^k + b_k*i^k)
		btcec.ScalarMultNonConst(i_power, e, term)
		// calculate prod(E_k^i^k)
		btcec.AddNonConst(calculated_c, term, calculated_c)
		i_power.Mul(participant_scalar)
	}

	calculated_c.ToAffine()
	expected_c.ToAffine()

	// check if the calculated commitment is equal to the expected commitment
	assert.Equal(s.t, expected_c.X, calculated_c.X)
}

// using Lagrange interpolation to reconstruct the secret polynomial
// Lagrange polynomials: multiplication of prod((x - x_l)/(x_i - x_l)), l != i, l = [1, t]
// evaluating Lagrange at x = 0 yields the secret: multiplication of (-x_l)/(x_i - x_l) for i != l, from 1 to t
// Larange interpolation:
func (s *TestSuite) retrieveSecret(secret_shares map[int]*btcec.ModNScalar) *btcec.ModNScalar {
	secret := new(btcec.ModNScalar).SetInt(0)
	for i := 0; i < len(secret_shares); i++ {
		mul_j := new(btcec.ModNScalar).SetInt(1)
		for j := 0; j < len(secret_shares); j++ {
			if j != i {
				x_j := new(btcec.ModNScalar).SetInt(uint32(j + 1))
				x_i := new(btcec.ModNScalar).SetInt(uint32(i + 1))
				numerator := new(btcec.ModNScalar).NegateVal(x_j)
				denominator := new(btcec.ModNScalar).NegateVal(x_j).Add(x_i)
				mul_j.Mul(numerator)
				mul_j.Mul(denominator.InverseNonConst())
			}
		}
		term := new(btcec.ModNScalar).Mul2(secret_shares[i], mul_j)
		secret.Add(term)
	}

	return secret
}
