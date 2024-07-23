package testhelper

import btcec "github.com/btcsuite/btcd/btcec/v2"

// seem like FROST will be hevily used as a bitcoin building block
// thus, it will be re - used in many tests

type FrostParticipant struct {
	N        int
	Theshold int

	secretPolynomial      []*btcec.ModNScalar
	PolynomialCommitments []*btcec.PublicKey
}

func NewFrostParticipant(suite *TestSuite, n, theshold int, secret *btcec.ModNScalar) *FrostParticipant {
	frost := &FrostParticipant{
		N:        n,
		Theshold: theshold,
	}

	// generate secret polynomial
	frost.secretPolynomial = suite.GeneratePolynomial(theshold)
	if secret != nil {
		frost.secretPolynomial[0] = secret
	}
	// generate public polynomial commitments
	frost.PolynomialCommitments = frost.generatePedersenCommitments()

	return frost
}

// calculate A(k) = g^a_k
func (p *FrostParticipant) generatePedersenCommitments() []*btcec.PublicKey {
	commitments := make([]*btcec.PublicKey, p.Theshold)
	for i := 0; i < p.Theshold; i++ {
		// g^a_k
		point := new(btcec.JacobianPoint)
		btcec.ScalarBaseMultNonConst(p.secretPolynomial[i], point)
		point.ToAffine()
		commitments[i] = btcec.NewPublicKey(&point.X, &point.Y)
	}
	return commitments
}
