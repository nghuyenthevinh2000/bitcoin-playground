package main

import (
	"crypto/sha256"
	"log"
	"testing"

	btcec "github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/nghuyenthevinh2000/bitcoin-playground/testhelper"
	"github.com/stretchr/testify/assert"
)

var (
	// FROST_TAG is the tag used in the commitment hash
	FROST_TAG = []byte("FROST_TAG")
)

type FrostParticipant struct {
	// Pederson participant
	*PedersonParticipant

	// schnorr
	position     int
	context_hash [32]byte
	message_hash [32]byte
	secret_proof *schnorr.Signature

	// nonces management [0]: d, [1]: e
	this_participant_nonce        [2]*btcec.ModNScalar
	this_participant_public_nonce [2]*btcec.JacobianPoint
	other_nonces                  map[int][2]*btcec.JacobianPoint
	other_nonce_commitments       map[int]*btcec.JacobianPoint
	aggr_nonce_commitment         *btcec.JacobianPoint

	// signing
	// s_i = \sum_{j=1}^{n} f_j(i)
	signing_shares *btcec.ModNScalar
	// Y_i = g^s_i
	signing_verification_shares *btcec.JacobianPoint
	// other participants' signing commitments
	other_secret_commitments          map[int][]*btcec.PublicKey
	other_signing_verification_shares map[int]*btcec.JacobianPoint
}

// go test -v -count=10 -run ^TestCreateFrostParticipant$ github.com/nghuyenthevinh2000/bitcoin-playground
func TestCreateFrostParticipant(t *testing.T) {
	suite := testhelper.TestSuite{}
	suite.SetupStaticSimNetSuite(t, log.Default())

	n := 7
	thres := 5

	newFrostParticipantDKG(&suite, thres, n, 1)
}

// go test -v -run ^TestFrostCalculateShares$ github.com/nghuyenthevinh2000/bitcoin-playground
func TestFrostCalculateShares(t *testing.T) {
	suite := new(testhelper.TestSuite)
	suite.SetupStaticSimNetSuite(t, log.Default())
	participant := testhelper.NewFrostParticipant(suite, nil, 5, 3, 1, nil)
	assert.NotNil(t, participant)

	participant.CalculateSecretShares()
}

// this is a minimal FROST implementation for educational purposes
// an overview os its Schnorr signature:
// our setting has n = 7 participants, with threshold t = 5 participants
// go test -v -run ^TestFrostSignature$ github.com/nghuyenthevinh2000/bitcoin-playground
func TestFrostSignature(t *testing.T) {
	suite := testhelper.TestSuite{}
	suite.SetupStaticSimNetSuite(t, log.Default())

	n := 7
	thres := 5

	// STEP 1: Key generation
	// 1.1: each participant generates their Pederson secret shares, and secret commitments
	participants := make([]*FrostParticipant, n)
	for i := 0; i < n; i++ {
		participants[i] = newFrostParticipantDKG(&suite, thres, n, i+1)
	}

	// 1.2: participant broadcast secret public commitments and secret proofs
	// each participants verify received secret proofs
	// they want to address the deliberate bias of attacker shares
	// and denial of the honest shares (Gennaro)
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			if i == j {
				continue
			}
			participant := participants[j]
			participant.verifyFrostSecretProof(&suite,
				participant.position,
				participant.secret_proof,
				schnorr.SerializePubKey(participant.SecretCommitments[0]),
				participant.context_hash,
			)
		}
	}

	// 1.3: each participant sends their secret shares to all other participants
	// each participant verifies received secret shares
	for i := 0; i < n; i++ {
		this_participant_secret_shares := make(map[int]*btcec.ModNScalar)
		for j := 0; j < n; j++ {
			this_participant_secret_shares[j] = participants[j].PedersonParticipant.SecretShares[i]
			participants[i].other_secret_commitments[j] = participants[j].SecretCommitments

			participant_scalar := new(btcec.ModNScalar)
			participant_scalar.SetInt(uint32(i + 1))
			verifyPedersenPublicShares(&suite, this_participant_secret_shares[j], participants[j].SecretCommitments, participant_scalar)
		}

		participants[i].derivePublicVerificationShares(this_participant_secret_shares)
	}

	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			if i == j {
				continue
			}
			participants[i].calculateOtherPublicVerificationShares(j)

			// verify if calculated public verification shares are correct with participant j
			participants[i].other_signing_verification_shares[j].ToAffine()
			participants[j].signing_verification_shares.ToAffine()
			assert.Equal(t, participants[i].other_signing_verification_shares[j], participants[j].signing_verification_shares, "mismatch public verification shares")
		}
	}

	// derive the combined public key
	// Y = g^(\sum_{i=1}^{n} a_i0) = g^(\sum_{i=1}^{n} \sum_{j=1}^{t} \lambda_j * f_i(j))
	// with s_j = \sum_{i=1}^{n} f_i(j)
	// Y = g^(\sum_{j=1}^{t} \lambda_j * s_j) = \prod_{j=1}^{t} Y_j^(\lambda_j)
	aggr_pub_point := new(btcec.JacobianPoint)
	for i := 0; i < n; i++ {
		point := new(btcec.JacobianPoint)
		participants[i].SecretCommitments[0].AsJacobian(point)
		btcec.AddNonConst(aggr_pub_point, point, aggr_pub_point)
	}
	aggr_pub_point.ToAffine()
	for i := 0; i < n; i++ {
		participants[i].CombinedPublicKey = btcec.NewPublicKey(&aggr_pub_point.X, &aggr_pub_point.Y)
	}

	// verify that the combined signing_verification_shares equals the combined public key
	// with 5 honest participants
	calculated_y := new(btcec.JacobianPoint)
	for i := 0; i < thres; i++ {
		lambda_i := suite.CalculateLagrangeCoeff(int64(i+1), []int64{1, 2, 3, 4, 5})
		// Y_i^(\lambda_i)
		term := new(btcec.JacobianPoint)
		btcec.ScalarMultNonConst(lambda_i, participants[i].signing_verification_shares, term)
		btcec.AddNonConst(calculated_y, term, calculated_y)
	}
	calculated_y.ToAffine()
	assert.Equal(t, calculated_y.X, aggr_pub_point.X, "mismatch combined public key")

	// verify that all participants have the same combined public key
	for i := 0; i < n; i++ {
		for j := i; j < n; j++ {
			assert.Equal(t, participants[i].CombinedPublicKey, participants[j].CombinedPublicKey, "mismatch combined public key")
		}
	}

	// STEP 2: Signing
	// 2.1: in pre - processing for each participant, generating two nonces (d, e)
	for i := 0; i < n; i++ {
		participants[i].generateSigningNonces(&suite)
	}

	// 2.2: each participant sends their public nonces to all other participants
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			participant := participants[j]
			participant.other_nonces[i] = participants[i].this_participant_public_nonce
		}
	}

	message := sha256.Sum256([]byte("a random message"))
	for i := 0; i < n; i++ {
		participants[i].message_hash = message
	}

	// 2.3: each participant computes the aggregated public nonce
	// Doing so binds the message, the set of signing participants,
	// and each participant’s commitment to each signature share.
	// This binding technique thwarts the attack of Drijvers et al.
	honest := []int{0, 2, 3, 5, 6}
	for _, i := range honest {
		participants[i].calculatePublicNonceCommitments(&suite, honest)
	}

	// check that all participants have the same combined public nonce commitment
	for i := range honest {
		for j := i; j < len(honest); j++ {
			assert.Equal(suite.T, participants[honest[i]].aggr_nonce_commitment, participants[honest[j]].aggr_nonce_commitment, "mismatch aggregated nonce commitment")
		}
	}

	// 2.4: each participant performs signing
	// at this stage, each participant has the public nonce commitments and public key
	// from other honest participants
	partialSigns := make(map[int]*schnorr.Signature)
	for _, i := range honest {
		partialSigns[i] = participants[i].partialSign(&suite, honest)
	}

	// 2.5: a leader collects all partial signatures and computes the aggregated signature
	// assume that this leader is the first honest participant
	// z = z_1 + z_2 + ... + z_t
	z := new(btcec.ModNScalar)
	for _, i := range honest {
		participants[honest[0]].verifyPartialSig(&suite, partialSigns[i], i, honest)
		// extract z_i from the partial signature
		z_i := new(btcec.ModNScalar)
		z_i.SetByteSlice(partialSigns[i].Serialize()[32:64])
		z.Add(z_i)
	}

	// z = \sum_{i=1}^{t} r_i + \sum_{i=1}^{t} \lambda_i * s_i * c
	// g^z = R * g^(\sum_{i=1}^{t} \lambda_i * s_i * c)
	// g^z = R * Y^c
	// R = g^z * Y^-c
	sig := schnorr.NewSignature(&participants[honest[0]].aggr_nonce_commitment.X, z)
	res := sig.Verify(message[:], participants[honest[0]].CombinedPublicKey)
	assert.True(t, res, "signature verification failed")
}

// for a new frost participant, they need to keep private (r, secret polynomial)
// and public (secret_proofs, secret_commitment, secret_shares)
func newFrostParticipantDKG(s *testhelper.TestSuite, thres, n, position int) *FrostParticipant {
	participant := &FrostParticipant{
		position:                          position,
		other_nonces:                      make(map[int][2]*btcec.JacobianPoint),
		other_nonce_commitments:           make(map[int]*btcec.JacobianPoint),
		aggr_nonce_commitment:             new(btcec.JacobianPoint),
		signing_shares:                    new(btcec.ModNScalar),
		signing_verification_shares:       new(btcec.JacobianPoint),
		other_secret_commitments:          make(map[int][]*btcec.PublicKey),
		other_signing_verification_shares: make(map[int]*btcec.JacobianPoint),
	}
	participant.PedersonParticipant = newPedersonParticipantDKG(s, thres, n)

	// calculating this participant secret proof
	nonce := s.Generate32BSeed()
	r := new(btcec.ModNScalar)
	r.SetBytes(&nonce)
	R := new(btcec.JacobianPoint)
	btcec.ScalarBaseMultNonConst(r, R)
	R.ToAffine()
	if R.Y.IsOdd() {
		r.Negate()
	}

	secret := participant.testSecretPolynomial[0]
	secret_commitment_bytes := participant.SecretCommitments[0].SerializeCompressed()
	if secret_commitment_bytes[0] == secp.PubKeyFormatCompressedOdd {
		secret.Negate()
	}

	// calculating commitment hash
	// c = H(i, stamp, A_i, R_i)
	participant.context_hash = sha256.Sum256([]byte("a random context"))
	commitment_data := make([]byte, 0)
	commitment_data = append(commitment_data, byte(participant.position))
	commitment_data = append(commitment_data, participant.context_hash[:]...)
	commitment_data = append(commitment_data, schnorr.SerializePubKey(participant.SecretCommitments[0])...)
	commitment_data = append(commitment_data, R.X.Bytes()[:]...)

	commitment_hash := chainhash.TaggedHash(FROST_TAG, commitment_data)
	c := new(btcec.ModNScalar)
	c.SetByteSlice(commitment_hash[:])

	s_scalar := new(btcec.ModNScalar).Mul2(secret, c).Add(r)
	sig := schnorr.NewSignature(&R.X, s_scalar)

	// self - verify that the calculation is correct
	participant.verifyFrostSecretProof(s, position, sig, schnorr.SerializePubKey(participant.SecretCommitments[0]), participant.context_hash)

	participant.secret_proof = sig
	return participant
}

// derive the public verification shares from the collected secret shares
// s_i = \sum_{j=1}^{n} f_j(i)
// Y_i = g^s_i
func (participant *FrostParticipant) derivePublicVerificationShares(collected_secret_shares map[int]*btcec.ModNScalar) {
	participant.signing_shares.SetInt(0)
	for _, share := range collected_secret_shares {
		participant.signing_shares.Add(share)
	}

	btcec.ScalarBaseMultNonConst(participant.signing_shares, participant.signing_verification_shares)

	// for easier calculation
	participant.other_signing_verification_shares[participant.position-1] = participant.signing_verification_shares
}

// calculate Y_i from other participant secret commitments
// recall that Y_i = g^s_i
// s_i = \sum_{i=1}^{n} f_j(i)
// thus, Y_i = g^(\sum_{i=1}^{n} f_j(i)) = \prod_{i=1}^{n} g^{f_j(i)}
// Y_i = \prod_{i=1}^{n} g^{\sum_{j=0}^{t-1} a_ij * i^j}
// Y_i = \prod_{i=1}^{n} \prod_{j=0}^{t-1} g^{a_ij * i^j}
// Y_i = \prod_{i=1}^{n} \prod_{j=0}^{t-1} A_ij^i^k
func (participant *FrostParticipant) calculateOtherPublicVerificationShares(other_posi int) {
	other_posi_scalar := new(btcec.ModNScalar)
	other_posi_scalar.SetInt(uint32(other_posi + 1))

	Y := new(btcec.JacobianPoint)
	for i := 0; i < participant.N; i++ {
		i_power := new(btcec.ModNScalar)
		i_power.SetInt(1)
		// \prod_{j=0}^{t-1} A_ij^i^k
		term := new(btcec.JacobianPoint)
		for j := 0; j < participant.Threshold; j++ {
			// A_ij
			A_ij := new(btcec.JacobianPoint)
			participant.other_secret_commitments[i][j].AsJacobian(A_ij)

			// calculate A_ij^i^k
			term1 := new(btcec.JacobianPoint)
			btcec.ScalarMultNonConst(i_power, A_ij, term1)

			btcec.AddNonConst(term, term1, term)

			i_power.Mul(other_posi_scalar)
		}
		btcec.AddNonConst(Y, term, Y)
	}
	Y.ToAffine()

	participant.other_signing_verification_shares[other_posi] = Y
}

// generate two nonces (d, e)
func (participant *FrostParticipant) generateSigningNonces(s *testhelper.TestSuite) {
	// generate nonces (d, e) for each signing
	// for pi = 1 number of pairs
	d_seed := s.Generate32BSeed()
	e_seed := s.Generate32BSeed()

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

	participant.this_participant_nonce = [2]*btcec.ModNScalar{d, e}
	participant.this_participant_public_nonce = [2]*btcec.JacobianPoint{D, E}
}

// with provided public nonces from other participants, calculate the aggregated public nonce commitments
// R_i = D_i * E_i ^ p_i
// p_i = H(i, m, B)
// B = {D_1, E_1, ..., D_t, E_t}
// where B is the set of public nonces from t participants
// and m is the message to be signed
// and i is the participant's position
func (participant *FrostParticipant) calculatePublicNonceCommitments(_ *testhelper.TestSuite, honest []int) {
	// calculate p_i for each honest participants
	p_data := make([]byte, 0)
	p_data = append(p_data, participant.message_hash[:]...)
	for _, j := range honest {
		D := participant.other_nonces[j][0]
		E := participant.other_nonces[j][1]
		p_data = append(p_data, D.X.Bytes()[:]...)
		p_data = append(p_data, E.X.Bytes()[:]...)
	}

	p_list := make(map[int]*btcec.ModNScalar)
	for _, i := range honest {
		p_i_data := append([]byte{byte(i + 1)}, p_data...)
		p := chainhash.HashB(p_i_data)
		p_scalar := new(btcec.ModNScalar)
		p_scalar.SetByteSlice(p)

		p_list[i] = p_scalar
	}

	// calculate R and R_i
	for _, i := range honest {
		// E_i ^ p_i
		term := new(btcec.JacobianPoint)
		btcec.ScalarMultNonConst(p_list[i], participant.other_nonces[i][1], term)
		// R_i = D_i * E_i ^ p_i
		R_i := new(btcec.JacobianPoint)
		btcec.AddNonConst(participant.other_nonces[i][0], term, R_i)
		R_i.ToAffine()

		participant.other_nonce_commitments[i] = R_i
		btcec.AddNonConst(participant.aggr_nonce_commitment, R_i, participant.aggr_nonce_commitment)
	}
	participant.aggr_nonce_commitment.ToAffine()
}

// construct z_i = d_i + e_i * p_i + \lambda_i * s_i * c
// \lambda_i is the Lagrange coefficient for the participant i over the honest participants
// s_i is the long-term secret share of participant i
// c = H(R, Y, m)
// TODO: have not checked for even or odd Y - coordinates
func (participant *FrostParticipant) partialSign(suite *testhelper.TestSuite, honest []int) *schnorr.Signature {
	// calculate c
	commitment_data := make([]byte, 0)
	commitment_data = append(commitment_data, participant.aggr_nonce_commitment.X.Bytes()[:]...)
	commitment_data = append(commitment_data, schnorr.SerializePubKey(participant.CombinedPublicKey)...)
	commitment_data = append(commitment_data, participant.message_hash[:]...)
	commitment_hash := chainhash.TaggedHash(chainhash.TagBIP0340Challenge, commitment_data)
	c := new(btcec.ModNScalar)
	c.SetByteSlice(commitment_hash[:])

	// calculate p_i
	p_i_data := make([]byte, 0)
	p_i_data = append(p_i_data, byte(participant.position))
	p_i_data = append(p_i_data, participant.message_hash[:]...)
	for _, i := range honest {
		D := participant.other_nonces[i][0]
		E := participant.other_nonces[i][1]
		p_i_data = append(p_i_data, D.X.Bytes()[:]...)
		p_i_data = append(p_i_data, E.X.Bytes()[:]...)
	}
	p_i := chainhash.HashB(p_i_data)
	p_i_scalar := new(btcec.ModNScalar)
	p_i_scalar.SetByteSlice(p_i)

	// d_i, e_i
	d_i := new(btcec.ModNScalar).Set(participant.this_participant_nonce[0])
	e_i := new(btcec.ModNScalar).Set(participant.this_participant_nonce[1])
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
	if participant.aggr_nonce_commitment.Y.IsOdd() {
		d_i.Negate()
		e_i.Negate()
	}

	s_i := participant.signing_shares
	if participant.CombinedPublicKey.SerializeCompressed()[0] == secp.PubKeyFormatCompressedOdd {
		suite.Logger.Printf("participant %d, CombinedPublicKey is odd", participant.position)
		s_i.Negate()
	}

	// calculate larange coefficient
	lamba := suite.CalculateLagrangeCoeff(int64(participant.position), convertArrInt64WithStart1(honest))
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

// \sigma_i = (R_i, \mu_i)
// recall that: \mu_i = k_i + a_i0 * c
// thus, g^\mu_i = g^k_i * g^{a_i0 * c} = R_i * A_i0^c
// thus R_i = g^\mu_i * A_i0^-c
// schnorr pubkey contains only the x-coordinate, thus need to be careful around working with schnorr - compatible public key since it requires only x - coordinate
func (participant *FrostParticipant) verifyFrostSecretProof(suite *testhelper.TestSuite, other_posi int, secret_proof *schnorr.Signature, secret_commitment_bytes []byte, stamp_hash [32]byte) {
	// recalculating commitment hash c
	secret_proof_bytes := secret_proof.Serialize()
	R_bytes := secret_proof_bytes[0:32]
	R_X := new(btcec.FieldVal)
	R_X.SetByteSlice(R_bytes)
	s_bytes := secret_proof_bytes[32:64]
	s := new(btcec.ModNScalar)
	s.SetByteSlice(s_bytes)

	// c = H(i, stamp, A_i, R_i)
	commitment_data := make([]byte, 0)
	commitment_data = append(commitment_data, byte(other_posi))
	commitment_data = append(commitment_data, stamp_hash[:]...)
	commitment_data = append(commitment_data, secret_commitment_bytes[:]...)
	commitment_data = append(commitment_data, R_bytes...)

	commitment_hash := chainhash.TaggedHash(FROST_TAG, commitment_data)
	c := new(btcec.ModNScalar)
	c.SetByteSlice(commitment_hash[:])

	R := new(btcec.JacobianPoint)
	// A_i0^-c
	secret_commitment_pubkey, err := schnorr.ParsePubKey(secret_commitment_bytes)
	assert.Nil(suite.T, err)
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
	assert.False(suite.T, is_infinity, "verify frost secret proof: R is the point at infinity")

	// R_Y cannot be odd
	R.ToAffine()
	assert.False(suite.T, R.Y.IsOdd(), "verify frost secret proof: R.Y is odd")

	// verify R point equals provided R_X
	assert.Equal(suite.T, &R.X, R_X, "verify frost secret proof: R.X does not match provided R_X")
}

// verifying the partial signature from each honest participant
// recall that: z_i = d_i + e_i * p_i + \lambda_i * s_i * c
// thus, g^z_i = R_i * g^(\lambda_i * s_i * c) = R_i * Y_i^(\lambda_i * c)
// thus, R_i = g^z_i * Y_i^-(\lambda_i * c)
func (participant *FrostParticipant) verifyPartialSig(suite *testhelper.TestSuite, sig *schnorr.Signature, other_posi int, honest []int) {
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
	commitment_data = append(commitment_data, participant.aggr_nonce_commitment.X.Bytes()[:]...)
	commitment_data = append(commitment_data, schnorr.SerializePubKey(participant.CombinedPublicKey)...)
	commitment_data = append(commitment_data, participant.message_hash[:]...)
	commitment_hash := chainhash.TaggedHash(chainhash.TagBIP0340Challenge, commitment_data)
	c := new(btcec.ModNScalar)
	c.SetByteSlice(commitment_hash[:])

	c.Negate()

	// extract Y_i X only
	Y_i := participant.other_signing_verification_shares[other_posi]
	if participant.CombinedPublicKey.SerializeCompressed()[0] == secp.PubKeyFormatCompressedOdd {
		Y_i.Y.Negate(1)
		Y_i.Y.Normalize()
	}

	// \lambda_i * c
	term := new(btcec.ModNScalar)
	lambda := suite.CalculateLagrangeCoeff(int64(other_posi+1), convertArrInt64WithStart1(honest))
	term.Mul2(lambda, c)
	// Y_i^-(\lambda_i * c)
	term1 := new(btcec.JacobianPoint)
	btcec.ScalarMultNonConst(term, Y_i, term1)
	// g^z_i
	term2 := new(btcec.JacobianPoint)
	btcec.ScalarBaseMultNonConst(z, term2)
	// R_i = g^z_i * Y_i^-(\lambda_i * c)
	R := new(btcec.JacobianPoint)
	btcec.AddNonConst(term2, term1, R)

	// Fail if R is the point at infinity
	is_infinity := false
	if (R.X.IsZero() && R.Y.IsZero()) || R.Z.IsZero() {
		is_infinity = true
	}
	assert.False(suite.T, is_infinity, "verify partial sig proof: R is the point at infinity")

	R.ToAffine()

	// verify R point equals provided R_X
	assert.Equal(suite.T, &R.X, R_X, "verify partial sig proof: R.X does not match provided R_X")
}

// due to some later changes with stricter enforcement of array position
func convertArrInt64WithStart1(honest []int) []int64 {
	honest_int64 := make([]int64, len(honest))
	for i, h := range honest {
		honest_int64[i] = int64(h + 1)
	}
	return honest_int64
}
