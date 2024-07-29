package main

import (
	"testing"

	btcec "github.com/btcsuite/btcd/btcec/v2"
	"github.com/nghuyenthevinh2000/bitcoin-playground/testhelper"
	"github.com/stretchr/testify/assert"
)

// witness - execution oracle test
var (
	// 7 oracles seed
	// TODO: using seed to deterministically generate coefficients for polynomial
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

type GennaroParticipant struct {
	*PedersonParticipant

	// used for testing only, not exposed privately
	testCommitmentPolynomial []*btcec.ModNScalar

	// the reason for commitment shares here is for it to be multiplied with the secret shares to derive commitments
	// as such, the secret shares cannot be changed without changing the commitment shares
	CommitmentShares map[int]*btcec.ModNScalar
	Commitments      []*btcec.PublicKey

	// combined commitment shares from all participants to derive this participant commitment shares
	CombinedCommitmentShares *btcec.ModNScalar
}

type PedersonParticipant struct {
	// used for testing only, not exposed privately
	testSecretPolynomial []*btcec.ModNScalar
	Threshold            int
	N                    int

	// secret shares are calculated as f(i)
	SecretShares map[int]*btcec.ModNScalar
	// secret commitment is calculated as A_k = g^a_k, k = [0, t]
	SecretCommitments []*btcec.PublicKey

	// combined public point from all participants
	CombinedPublicKey *btcec.PublicKey
	// combined secret shares from all participants to derive this participant secret shares
	CombinedSecretShares *btcec.ModNScalar
}

// go test -v -run ^TestCreatePerdersonParticipant$ github.com/nghuyenthevinh2000/bitcoin-playground
func TestCreatePerdersonParticipant(t *testing.T) {
	suite := testhelper.TestSuite{}
	suite.SetupStaticSimNetSuite(t)
	defer suite.StaticSimNetTearDown()

	threshold := 5
	participant_num := 7
	participant := newPedersonParticipantDKG(&suite, threshold, participant_num)
	assert.NotNil(t, participant)
}

// go test -v -run ^TestBasicGennaroDKG$ github.com/nghuyenthevinh2000/bitcoin-playground
// Test the very basic Gennaro Distributed Key Generation (DKG) protocol
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
// 1. commitments of coefficients of both secret and commitment polynomial: E(k) = g^(a_k + b_k) = g^e_k
// 2. commitments of coefficients of secret polynomial (the one that contains secret): A(k) = g^a_k
// 3. commitments of secret shares: C(i) = g^(f(i) + h(i)) = prod(E(k)^i^k), k = [0, t]
func TestBasicGennaroDKG(t *testing.T) {
	s := testhelper.TestSuite{}
	s.SetupStaticSimNetSuite(t)
	defer s.StaticSimNetTearDown()

	// setup 7 participants
	// threshold = 5
	threshold := 5
	participants := make([]*GennaroParticipant, len(oracles))

	// In the Gennaro DKG scheme, each participant generates
	// two polynomials: one for the secret shares and another for the commitments.
	// The commitments polynomial helps in proving that the shares
	// are valid without revealing the actual secret.
	// if each
	for i := range participants {
		participants[i] = newGennaroParticipantDKG(&s, threshold, len(oracles))
	}

	// commitment round: Gennaro et al. demonstrate a weakness of Pedersen’s DKG such that a
	// misbehaving participant can bias the distribution of the resulting shared secret by
	// issuing complaints against a participant after seeing the shares issued to them by this
	// participant, thereby disqualifying them from contributing to the key generation.
	// To prevent adversaries from adaptively disqualifying participants based on their input,
	// the authors add an additional “commitment round”, such that the value of the resulting secret
	// is determined after participants perform this commitment round (before having revealed their inputs).
	//
	// participant i will then receive the shares from all other participants n in the network
	// each participant will verify the shares they received
	// each participant i receives f_k(i), and h_k(i) from all other participants k, k = [1, n]
	// they then check if what they receives matches the commitments proposed by participant k
	for i := 0; i < len(oracles); i++ {
		this_participant_secret_shares := make(map[int]*btcec.ModNScalar)
		this_pariticipant_commitment_shares := make(map[int]*btcec.ModNScalar)
		for k := 0; k < len(oracles); k++ {
			this_participant_secret_shares[k] = participants[k].SecretShares[i]
			this_pariticipant_commitment_shares[k] = participants[k].CommitmentShares[i]

			// verify the received shares
			participant_scalar := new(btcec.ModNScalar)
			participant_scalar.SetInt(uint32(i + 1))
			verifyGennaroPublicShares(&s, this_participant_secret_shares[k], this_pariticipant_commitment_shares[k], participants[k].Commitments, participant_scalar)
		}
	}

	// common public key derivation from a threshold number of participants
	// assuming that only a threshold t = 5 participants are honest after commitment round
	// verifying that the secret shares from each participant are verified against the secret commitments
	honest_participants := []int{0, 2, 3, 5, 6}
	for _, i := range honest_participants {
		this_participant_secret_shares := make(map[int]*btcec.ModNScalar)
		aggr_pub_point := new(btcec.JacobianPoint)
		for _, k := range honest_participants {
			this_participant_secret_shares[k] = participants[k].SecretShares[i]
			// verify the received secret shares
			participant_scalar := new(btcec.ModNScalar)
			participant_scalar.SetInt(uint32(i + 1))
			verifyPedersenPublicShares(&s, this_participant_secret_shares[k], participants[k].SecretCommitments, participant_scalar)
		}

		// once verified, the participants will then calculate the combined public key, and secret shares
		for _, k := range honest_participants {
			// calculate the combined public point
			point := new(btcec.JacobianPoint)
			participants[k].SecretCommitments[0].AsJacobian(point)
			btcec.AddNonConst(aggr_pub_point, point, aggr_pub_point)

			// calculate the combined secret shares
			participants[i].CombinedSecretShares.Add(this_participant_secret_shares[k])
		}
		// derive the combined public key
		aggr_pub_point.ToAffine()
		participants[i].CombinedPublicKey = btcec.NewPublicKey(&aggr_pub_point.X, &aggr_pub_point.Y)
	}

	// to retrieve the secret, each participants share their combined secret shares
	for _, i := range honest_participants {
		shared_combined_secret_shares := make(map[int]*btcec.ModNScalar)
		for _, k := range honest_participants {
			shared_combined_secret_shares[k] = participants[k].CombinedSecretShares
		}

		secret_scalar := retrieveSecret(&s, shared_combined_secret_shares)
		// verify the secret against public key
		calculated_public_point := new(btcec.JacobianPoint)
		btcec.ScalarBaseMultNonConst(secret_scalar, calculated_public_point)
		calculated_public_point.ToAffine()
		calculated_public_key := btcec.NewPublicKey(&calculated_public_point.X, &calculated_public_point.Y)
		assert.Equal(t, participants[i].CombinedPublicKey, calculated_public_key)
	}
}

func newGennaroParticipantDKG(s *testhelper.TestSuite, threshold, participant_num int) *GennaroParticipant {
	participant := &GennaroParticipant{
		PedersonParticipant: &PedersonParticipant{
			N:                    participant_num,
			Threshold:            threshold,
			SecretShares:         make(map[int]*btcec.ModNScalar),
			CombinedPublicKey:    new(btcec.PublicKey),
			CombinedSecretShares: new(btcec.ModNScalar),
		},
		CommitmentShares:         make(map[int]*btcec.ModNScalar),
		CombinedCommitmentShares: new(btcec.ModNScalar),
	}

	secretPolynomial := s.GeneratePolynomial(int64(threshold - 1))
	participant.testSecretPolynomial = secretPolynomial
	commitmentPolynomial := s.GeneratePolynomial(int64(threshold - 1))
	participant.testCommitmentPolynomial = commitmentPolynomial
	participant.SecretCommitments = participant.generatePedersenCommitments()
	participant.Commitments = participant.generateGennaroCommitments()

	// calculate shares for each participant
	for j := 0; j < participant_num; j++ {
		// evaluate the secret polynomial at the participant index
		participant_scalar := new(btcec.ModNScalar).SetInt(uint32(j + 1))
		// secret shares as f(x)
		participant.SecretShares[j] = s.EvaluatePolynomial(secretPolynomial, participant_scalar)
		// commitment shares as g(x)
		participant.CommitmentShares[j] = s.EvaluatePolynomial(commitmentPolynomial, participant_scalar)
	}

	// verify internal commitment and secret aggregated shares
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
		assert.Equal(s.T, e, sum_scalar, "internal verification: failed sum")

		// calculate prod(E_k^i^k)
		product := new(btcec.JacobianPoint)
		btcec.ScalarBaseMultNonConst(sum_scalar, product)

		expected_commitment.ToAffine()
		product.ToAffine()

		// check if the calculated commitment is equal to the expected commitment
		assert.Equal(s.T, expected_commitment.X, product.X, "internal verification of shares failed")
	}

	// verify internal secret shares
	// g^f(i) = g^(a_0 + a_1*i + a_2*i^2 + ... + a_t*i^t) = g^sum(a_k*i^k), k = [0, t]
	// g^sum(a_k*i^k) = prod(A_k^i^k), k = [0, t]
	for i := 0; i < participant_num; i++ {
		// expected value
		expected_secret := new(btcec.JacobianPoint)
		btcec.ScalarBaseMultNonConst(participant.SecretShares[i], expected_secret)

		participant_scalar := new(btcec.ModNScalar)
		participant_scalar.SetInt(uint32(i + 1))

		// calculate sum(a_k*i^k)
		i_power := new(btcec.ModNScalar)
		i_power.SetInt(1)
		sum_scalar := new(btcec.ModNScalar)
		sum_scalar.SetInt(0)
		for k := 0; k < threshold; k++ {
			// calculate term = a_k*i^k
			term := new(btcec.ModNScalar).Mul2(secretPolynomial[k], i_power)
			// calculate sum(a_k*i^k)
			sum_scalar.Add(term)
			// i^k
			i_power.Mul(participant_scalar)
		}

		// calculate prod(A_k^i^k)
		product := new(btcec.JacobianPoint)
		btcec.ScalarBaseMultNonConst(sum_scalar, product)

		expected_secret.ToAffine()
		product.ToAffine()

		// check if the calculated commitment is equal to the expected commitment
		assert.Equal(s.T, expected_secret.X, product.X, "internal verification of secret shares failed")
	}

	return participant
}

// calculate E_k = g^(a_k + b_k) = g^e_k
// compute commitment points for each polynomial coefficients
func (g *GennaroParticipant) generateGennaroCommitments() []*btcec.PublicKey {
	commitments := make([]*btcec.PublicKey, g.Threshold)
	for i := 0; i < g.Threshold; i++ {
		// a_k + b_k
		aggr_scalar := new(btcec.ModNScalar).Add2(g.testSecretPolynomial[i], g.testCommitmentPolynomial[i])
		// g^(f(x) + h(x))
		aggr_point := new(btcec.JacobianPoint)
		btcec.ScalarBaseMultNonConst(aggr_scalar, aggr_point)
		aggr_point.ToAffine()
		commitments[i] = btcec.NewPublicKey(&aggr_point.X, &aggr_point.Y)
	}
	return commitments
}

// each participant can verify share with (f(i), h(i), E)
// prod(E_k^i^k) = g^sum(e_k*i^k), k = [0, t]
func verifyGennaroPublicShares(suite *testhelper.TestSuite, secretShares, commitmentShares *btcec.ModNScalar, commitments []*btcec.PublicKey, participant_scalar *btcec.ModNScalar) {
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
	assert.Equal(suite.T, expected_c.X, calculated_c.X)
}

func newPedersonParticipantDKG(s *testhelper.TestSuite, threshold, participant_num int) *PedersonParticipant {
	participant := &PedersonParticipant{
		Threshold:            threshold,
		N:                    participant_num,
		SecretShares:         make(map[int]*btcec.ModNScalar),
		CombinedPublicKey:    new(btcec.PublicKey),
		CombinedSecretShares: new(btcec.ModNScalar),
	}

	secretPolynomial := s.GeneratePolynomial(int64(threshold - 1))
	participant.testSecretPolynomial = secretPolynomial
	participant.SecretCommitments = participant.generatePedersenCommitments()

	// calculate shares for each participant
	for j := 0; j < participant_num; j++ {
		// evaluate the secret polynomial at the participant index
		participant_scalar := new(btcec.ModNScalar).SetInt(uint32(j + 1))
		// secret shares as f(x)
		participant.SecretShares[j] = s.EvaluatePolynomial(secretPolynomial, participant_scalar)
	}

	// verify internal secret shares
	// g^f(i) = g^(a_0 + a_1*i + a_2*i^2 + ... + a_t*i^t) = g^sum(a_k*i^k), k = [0, t]
	// g^sum(a_k*i^k) = prod(A_k^i^k), k = [0, t]
	for i := 0; i < participant_num; i++ {
		// expected value
		expected_secret := new(btcec.JacobianPoint)
		btcec.ScalarBaseMultNonConst(participant.SecretShares[i], expected_secret)

		participant_scalar := new(btcec.ModNScalar)
		participant_scalar.SetInt(uint32(i + 1))

		// calculate sum(a_k*i^k)
		sum_scalar := s.EvaluatePolynomial(secretPolynomial, participant_scalar)

		// calculate prod(A_k^i^k)
		product := new(btcec.JacobianPoint)
		btcec.ScalarBaseMultNonConst(sum_scalar, product)

		expected_secret.ToAffine()
		product.ToAffine()

		// check if the calculated commitment is equal to the expected commitment
		assert.Equal(s.T, expected_secret.X, product.X, "internal verification of secret shares failed")
	}

	return participant
}

// calculate A(k) = g^a_k
func (p *PedersonParticipant) generatePedersenCommitments() []*btcec.PublicKey {
	commitments := make([]*btcec.PublicKey, len(p.testSecretPolynomial))
	for i := 0; i < len(p.testSecretPolynomial); i++ {
		// g^a_k
		point := new(btcec.JacobianPoint)
		btcec.ScalarBaseMultNonConst(p.testSecretPolynomial[i], point)
		point.ToAffine()
		commitments[i] = btcec.NewPublicKey(&point.X, &point.Y)
	}
	return commitments
}

func verifyPedersenPublicShares(s *testhelper.TestSuite, secretShares *btcec.ModNScalar, secretCommitments []*btcec.PublicKey, participant_scalar *btcec.ModNScalar) {
	// calculate A(i) = g^f(i)
	expected_a := new(btcec.JacobianPoint)
	btcec.ScalarBaseMultNonConst(secretShares, expected_a)

	// calculate prod(A_k^i^k)
	product := new(btcec.ModNScalar)
	product.SetInt(1)
	i_power := new(btcec.ModNScalar)
	i_power.SetInt(1)
	calculated_a := new(btcec.JacobianPoint)
	for i := 0; i < len(secretCommitments); i++ {
		term := new(btcec.JacobianPoint)
		secretCommitments[i].AsJacobian(term)
		// calculate term = A_k^i^k = g^(a_k*i^k)
		btcec.ScalarMultNonConst(i_power, term, term)
		// calculate prod(A_k^i^k)
		btcec.AddNonConst(calculated_a, term, calculated_a)
		i_power.Mul(participant_scalar)
	}

	calculated_a.ToAffine()
	expected_a.ToAffine()

	// check if the calculated commitment is equal to the expected commitment
	assert.Equal(s.T, expected_a.X, calculated_a.X)
}

// using Lagrange interpolation to reconstruct the secret polynomial
// Lagrange polynomials: multiplication of prod((x - x_l)/(x_i - x_l)), l != i, l = [1, t]
// evaluating Lagrange at x = 0 yields the secret: multiplication of (-x_l)/(x_i - x_l) for i != l, from 1 to t
// Larange interpolation:
func retrieveSecret(_ *testhelper.TestSuite, secret_shares map[int]*btcec.ModNScalar) *btcec.ModNScalar {
	secret := new(btcec.ModNScalar).SetInt(0)
	for i := range secret_shares {
		mul_j := new(btcec.ModNScalar).SetInt(1)
		for j := range secret_shares {
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
