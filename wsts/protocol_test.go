package wsts

import (
	"fmt"
	"log"
	"math/rand"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"cosmossdk.io/math"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	"github.com/nghuyenthevinh2000/bitcoin-playground/testhelper"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
)

const (
	// protocol storage
	VP_STORE_KEY                = "vp"
	KEY_RANGE_STORE_KEY         = "key_range"
	NONCE_COMMITMENTS_STORE_KEY = "nonce_commitments"
	TRANSACTION_STORE_KEY       = "transactions"

	// local storage
	SECRET_SHARES_STORE_KEY     = "secret_shares"
	LONG_TERM_SECRET_SHARES_KEY = "long_term_secret_shares"
)

var (
	MSG_VP_TYPE                  = byte(0)
	MSG_PROOFS_TYPE              = byte(1)
	MSG_SECRET_SHARES            = byte(2)
	MSG_STOP                     = byte(3)
	MSG_UPDATE_NONCE_COMMITMENTS = byte(4)
	MSG_WITHDRAW_BATCH           = byte(5)
)

var (
	// TODO: figure out what to put in context hash
	CONTEXT_HASH = [32]byte{}
)

// abstract the validator interface to force all validators to exchange through sending messages only
type ReceivableValidator interface {
	GetPosition() int64
	SendMessageOnChain(msg []byte)
	SendMessageOffChain(msg []byte)
	ReceiveMessageOnChainLoop()
	ReceiveMessageOffChainLoop()
}

// map index will start at 1
// array index will start at 0
type MockValidator struct {
	ReceivableValidator

	suite     *testhelper.TestSuite
	logger    *log.Logger
	file      *os.File
	keyPair   testhelper.KeyPair
	position  int64
	party_num int64
	frost     *testhelper.FrostParticipant
	otherVals map[int64]ReceivableValidator

	localStorage    MockProtocolStorage
	protocolStorage MockProtocolStorage

	msgChanOnChain  chan []byte
	msgChanOffChain chan []byte
}

func (v *MockValidator) GetPosition() int64 {
	return v.position
}

func (v *MockValidator) SendMessageOnChain(msg []byte) {
	v.msgChanOnChain <- msg
}

func (v *MockValidator) SendMessageOffChain(msg []byte) {
	v.msgChanOffChain <- msg
}

func (v *MockValidator) Stop() {
	v.SendMessageOnChain([]byte{MSG_STOP})
	v.SendMessageOffChain([]byte{MSG_STOP})
	v.file.Close()
}

// first bytes denote type of message
// need to make this function thread safe
func (v *MockValidator) ReceiveMessageOnChainLoop() {
	for {
		select {
		case msg := <-v.msgChanOnChain:
			msgType := msg[0]
			msgBytes := msg[1:]
			switch msgType {
			case MSG_VP_TYPE:
				msg := &MsgUpdateVP{}
				err := proto.Unmarshal(msgBytes, msg)
				assert.NoError(v.suite.T, err)
				v.protocolStorage.store[VP_STORE_KEY][strconv.FormatInt(msg.Source, 10)] = msg.Vp
			case MSG_PROOFS_TYPE:
				msg := &MsgUpdateProofs{}
				err := proto.Unmarshal(msgBytes, msg)
				assert.NoError(v.suite.T, err)
				// assert secret proofs
				secretProofs, err := schnorr.ParseSignature(msg.SecretProofs)
				assert.NoError(v.suite.T, err)
				secretCommitments, err := btcec.ParsePubKey(msg.PolynomialCommitments[0])
				assert.NoError(v.suite.T, err)
				v.frost.VerifySecretProofs(CONTEXT_HASH, secretProofs, msg.Source, secretCommitments)
				// store polynomial commitments
				v.storePolyCommitments(msg.Source, msg.PolynomialCommitments)
			case MSG_UPDATE_NONCE_COMMITMENTS:
				msg := &MsgUpdateNonceCommitments{}
				err := proto.Unmarshal(msgBytes, msg)
				assert.NoError(v.suite.T, err)
				// store nonce commitments
				for i, nonceCommitment := range msg.NonceCommitments {
					nonceStructBytes, err := proto.Marshal(nonceCommitment)
					assert.NoError(v.suite.T, err)
					v.storeNonceCommitments(msg.Source, int64(i), nonceStructBytes)
				}
			case MSG_WITHDRAW_BATCH:
				msg := &MsgBatchWithdraw{}
				err := proto.Unmarshal(msgBytes, msg)
				assert.NoError(v.suite.T, err)
				// store new transactions on - chain
				v.storeTxs(msg.WithdrawBatch)
			case MSG_STOP:
				return
			default:
				v.logger.Printf("Unknown message type: %d\n", msgType)
			}
		case <-time.After(3000 * time.Millisecond):
			v.logger.Printf("Validator %d: no new on - chain message after 3s\n", v.position)
		}
	}
}

func (v *MockValidator) ReceiveMessageOffChainLoop() {
	for {
		select {
		case msg := <-v.msgChanOffChain:
			msgType := msg[0]
			msgBytes := msg[1:]
			switch msgType {
			case MSG_SECRET_SHARES:
				msgStruct := &MsgSecretShares{}
				err := proto.Unmarshal(msgBytes, msgStruct)
				assert.NoError(v.suite.T, err)
				v.logger.Printf("received msg from source: %d, with num of keys: %d\n", msgStruct.Source, len(msgStruct.SecretShares))

				// there is a case where a validator has not yet constructed its key range, but received msg too soon
				if !v.protocolStorage.CheckKeyRangeExist(strconv.FormatInt(v.position, 10)) {
					v.logger.Printf("Key range has not been set for validator %d\n", v.position)
					go func() {
						time.Sleep(1000 * time.Millisecond)
						v.msgChanOffChain <- msg
					}()
					break
				}

				for _, secretShare := range msgStruct.SecretShares {
					// TODO: figure out what to do if received secret share is not in range
					if !v.protocolStorage.IsKeyInRange(strconv.FormatInt(v.position, 10), secretShare.Posi) {
						v.logger.Printf("Secret share %d is not in range for validator %d, from source: %d, expected: %v\n", secretShare.Posi, v.position, msgStruct.Source, v.protocolStorage.GetKeyRange(strconv.FormatInt(v.position, 10)))
						continue
					}

					// persist secret shares
					v.localStorage.SetSecretShares(msgStruct.Source, secretShare.Posi, secretShare.SecretShares)
				}

				// check if this validator has received all secret shares
				// range_key * party_num
				range_key := v.protocolStorage.GetKeyRange(strconv.FormatInt(v.position, 10))
				total_keys := (range_key[1] - range_key[0]) * v.party_num
				accumulated_keys := int64(len(v.localStorage.store[SECRET_SHARES_STORE_KEY]))
				v.logger.Printf("validator %d needs more keys %d\n", v.position, total_keys-accumulated_keys)
				if accumulated_keys == total_keys {
					v.logger.Printf("All secret shares have been received for validator %d\n", v.position)
					v.verifySharesAndCalculateLongTermKey()
				}

				// TODO: what will happen if never receive enough secret shares
			case MSG_STOP:
				return
			default:
				v.logger.Printf("Unknown message type: %d\n", msgType)
			}
		case <-time.After(3000 * time.Millisecond):
			v.logger.Printf("Validator %d: no new off - chain message after 3s\n", v.position)
		}
	}
}

func (v *MockValidator) SendVPToAll() {
	vp_bytes := v.protocolStorage.store[VP_STORE_KEY][strconv.FormatInt(v.position, 10)]
	msg := MsgUpdateVP{
		Source: v.position,
		Vp:     vp_bytes,
	}
	msgBytes, err := proto.Marshal(&msg)
	assert.NoError(v.suite.T, err)

	for _, otherVal := range v.otherVals {
		otherVal.SendMessageOnChain(append([]byte{MSG_VP_TYPE}, msgBytes...))
	}
}

// derive secret proof for this signing party
func (v *MockValidator) DeriveAndSendProofs() {
	// derive secret proof
	secret := v.frost.CalculateSecretProofs(CONTEXT_HASH)

	polynomialCommitmentsBytes := make([][]byte, v.frost.Theshold+1)
	for i := int64(0); i <= v.frost.Theshold; i++ {
		polynomialCommitmentsBytes[i] = v.frost.PolynomialCommitments[v.position][i].SerializeCompressed()
	}

	// self - update
	v.storePolyCommitments(v.position, polynomialCommitmentsBytes)

	msg := MsgUpdateProofs{
		Source:                v.position,
		SecretProofs:          secret.Serialize(),
		PolynomialCommitments: polynomialCommitmentsBytes,
	}
	msgBytes, err := proto.Marshal(&msg)
	assert.NoError(v.suite.T, err)

	for _, otherVal := range v.otherVals {
		otherVal.SendMessageOnChain(append([]byte{MSG_PROOFS_TYPE}, msgBytes...))
	}
}

func (v *MockValidator) DeriveAndSendSecretShares() {
	v.logger.Printf("Derive and send secret shares for validator %d\n", v.position)

	// calculate secret shares for all keys
	v.frost.CalculateSecretShares()

	// determine how many keys to send to other validators
	// based on the latest vp
	range_keys := v.DeriveRangeOfKeys()

	// save range of keys
	for i, range_key := range range_keys {
		v.protocolStorage.SetKeyRange(strconv.FormatInt(i, 10), range_key)
	}

	v.logger.Printf("Range of keys for validator %d: %v\n", v.position, range_keys)

	shares := v.frost.AllSecretShares()
	for i, share := range shares {
		v.logger.Printf("validator %d, index: %d, share: %v\n", v.position, i, share)
	}

	// save this validator secret shares
	for i := range_keys[v.position][0]; i < range_keys[v.position][1]; i++ {
		secretShare := v.frost.GetSecretShares(i)
		secretShareBytes := secretShare.Bytes()
		v.localStorage.SetSecretShares(v.position, i, secretShareBytes[:])
	}

	// send secret shares to all other validators
	for i, range_key := range range_keys {
		if i == v.position {
			continue
		}

		start := range_key[0]
		end := range_key[1]
		secretShares := make([]*SecretShares, 0)
		for j := start; j < end; j++ {
			secretShare := v.frost.GetSecretShares(j)
			secretShareBytes := secretShare.Bytes()

			secretShares = append(secretShares, &SecretShares{
				Posi:         j,
				SecretShares: secretShareBytes[:],
			})
		}

		// send batch to reduce message exchange
		secretShareMsg := MsgSecretShares{
			Source:       v.position,
			SecretShares: secretShares,
		}
		secretShareMsgBytes, err := proto.Marshal(&secretShareMsg)
		assert.NoError(v.suite.T, err)

		v.otherVals[i].SendMessageOffChain(append([]byte{MSG_SECRET_SHARES}, secretShareMsgBytes...))
	}
}

func (v *MockValidator) DeriveAndSendNonces() {
	// calculate nonce commitments
	// send nonce commitments to all other validators
	nonceCommitments := v.frost.GenerateSigningNonces(1)

	// store this validator nonce commitments
	nonceCommitmentsArr := make([]*NonceCommitments, len(nonceCommitments))
	for i, nonceCommitment := range nonceCommitments {
		nonceStruct := &NonceCommitments{
			D: nonceCommitment[0].SerializeCompressed(),
			E: nonceCommitment[1].SerializeCompressed(),
		}
		nonceCommitmentsArr[i] = nonceStruct
		nonceStructBytes, err := proto.Marshal(nonceStruct)
		assert.NoError(v.suite.T, err)

		v.storeNonceCommitments(v.position, int64(i), nonceStructBytes)
	}

	// send to all other validators
	for _, otherVal := range v.otherVals {
		msg := MsgUpdateNonceCommitments{
			Source:           v.position,
			NonceCommitments: nonceCommitmentsArr,
		}

		msgBytes, err := proto.Marshal(&msg)
		assert.NoError(v.suite.T, err)

		otherVal.SendMessageOnChain(append([]byte{MSG_UPDATE_NONCE_COMMITMENTS}, msgBytes...))
	}
}

// determine how many keys a validator will produce
// based on the latest vp
func (v *MockValidator) DeriveRangeOfKeys() map[int64][2]int64 {
	party_keys := make(map[int64]int64)
	// include this validator party
	total := int64(0)

	// temporarily add this validator to otherVals for complete iteration over all validators
	v.otherVals[v.position] = v
	// each validator will produce an amount of keys based on their VP
	for _, other := range v.otherVals {
		if other.GetPosition() == 1 {
			continue
		}
		vp_bytes := v.protocolStorage.store[VP_STORE_KEY][strconv.FormatInt(other.GetPosition(), 10)]
		vp := bytesToVp(v.suite, vp_bytes)
		expected_keys := vp.MulInt64(int64(v.frost.N)).RoundInt().Int64()
		// expected keys cannot be 0
		if expected_keys == 0 {
			expected_keys += 1
		}
		party_keys[other.GetPosition()] = expected_keys
		total += expected_keys
	}
	party_keys[1] = v.frost.N - total

	// remove temporary add
	delete(v.otherVals, v.position)

	// derive range of keys for each party
	range_keys := make(map[int64][2]int64)
	start := int64(1)
	for i := int64(1); i <= v.party_num; i++ {
		end := start + party_keys[i]
		range_keys[i] = [2]int64{start, end}
		start = end
	}
	assert.Equal(v.suite.T, v.party_num, int64(len(range_keys)))

	return range_keys
}

func (v *MockValidator) verifySharesAndCalculateLongTermKey() {
	// extract secret shares of a key from all validators
	key_range := v.protocolStorage.GetKeyRange(strconv.FormatInt(v.position, 10))
	for i := key_range[0]; i < key_range[1]; i++ {
		for j := int64(1); j <= v.party_num; j++ {
			secretShares := v.localStorage.GetSecretShares(j, i)
			// verify secret shares
			commitments := v.getPolyCommitments(j)
			var wg sync.WaitGroup
			wg.Add(1)
			go func(secretShares *btcec.ModNScalar, commitments []*btcec.PublicKey, posi int64) {
				v.frost.VerifyPublicSecretShares(secretShares, commitments, uint32(posi))
				wg.Done()
			}(secretShares, commitments, i)
			wg.Wait()
		}
	}

	// calculate long term key
	// can parallelize this process further
	for i := key_range[0]; i < key_range[1]; i++ {
		longTermShares := new(btcec.ModNScalar)
		longTermShares.SetInt(0)
		for j := int64(1); j <= v.party_num; j++ {
			secretShares := v.localStorage.GetSecretShares(j, i)
			longTermShares.Add(secretShares)
		}
		longTermSharesBytes := longTermShares.Bytes()
		v.localStorage.SetLongTermSecretShares(i, longTermSharesBytes[:])

		// calculate public signing shares
		key := v.frost.CalculateInternalPublicSigningShares(longTermShares, i)
		v.logger.Printf("key %d, long term key: %v\n", i, key)
	}

	// calculate public signing shares of all others
	all_poly_commitments := v.getAllPolyCommitments()
	for i := int64(1); i <= v.party_num; i++ {
		if i == v.position {
			continue
		}
		key_range := v.protocolStorage.GetKeyRange(strconv.FormatInt(i, 10))
		for j := key_range[0]; j < key_range[1]; j++ {
			key := v.frost.CalculatePublicSigningShares(v.party_num, j, all_poly_commitments)
			v.logger.Printf("for validator %d, key %d, long term key: %v\n", i, j, key)
		}
	}

	// calculate group public key
	groupkey := v.frost.CalculateGroupPublicKey(v.party_num)
	v.logger.Printf("group public key: %v\n", groupkey)
}

func (v *MockValidator) storePolyCommitments(posi int64, commitments [][]byte) {
	var err error
	poly_commitments := make([]*btcec.PublicKey, v.frost.Theshold+1)
	for i := int64(0); i <= v.frost.Theshold; i++ {
		poly_commitments[i], err = btcec.ParsePubKey(commitments[i])
		assert.NoError(v.suite.T, err)
	}
	v.frost.UpdatePolynomialCommitments(posi, poly_commitments)
}

func (v *MockValidator) getPolyCommitments(posi int64) []*btcec.PublicKey {
	return v.frost.PolynomialCommitments[posi]
}

func (v *MockValidator) getAllPolyCommitments() map[int64][]*btcec.PublicKey {
	commitments := make(map[int64][]*btcec.PublicKey)
	for i := int64(1); i <= v.party_num; i++ {
		commitments[i] = v.getPolyCommitments(i)
	}
	return commitments
}

func (v *MockValidator) storeTxs(txs []*MsgWithdraw) {
	for i, tx := range txs {
		txBytes, err := proto.Marshal(tx)
		assert.NoError(v.suite.T, err)
		v.protocolStorage.store[TRANSACTION_STORE_KEY][strconv.Itoa(i)] = txBytes
	}
}

func (v *MockValidator) getAllTxs() []*MsgWithdraw {
	txs := make([]*MsgWithdraw, 0)
	for i := 0; ; i++ {
		txBytes := v.protocolStorage.store[TRANSACTION_STORE_KEY][strconv.Itoa(i)]
		if len(txBytes) == 0 {
			break
		}
		tx := &MsgWithdraw{}
		err := proto.Unmarshal(txBytes, tx)
		assert.NoError(v.suite.T, err)
		txs = append(txs, tx)
	}

	return txs
}

func (v *MockValidator) storeNonceCommitments(posi, signing_index int64, commitments []byte) {
	substore_key := NONCE_COMMITMENTS_STORE_KEY + strconv.FormatInt(signing_index, 10)
	v.protocolStorage.store[substore_key] = make(map[string][]byte)
	v.protocolStorage.store[substore_key][strconv.FormatInt(posi, 10)] = commitments
}

func (v *MockValidator) getNonceCommitments(signing_index, posi int64) [2]*btcec.PublicKey {
	substore_key := NONCE_COMMITMENTS_STORE_KEY + strconv.FormatInt(signing_index, 10)
	commitment_bytes := v.protocolStorage.store[substore_key][strconv.FormatInt(posi, 10)]
	commitment := &NonceCommitments{}
	err := proto.Unmarshal(commitment_bytes, commitment)
	assert.NoError(v.suite.T, err)

	D, err := btcec.ParsePubKey(commitment.D)
	assert.NoError(v.suite.T, err)

	E, err := btcec.ParsePubKey(commitment.E)
	assert.NoError(v.suite.T, err)

	return [2]*btcec.PublicKey{D, E}
}

// serving as mock on - chain storage in each mock validator
// and all validator need to have the same storage data
//
// TODO: implement a merkle tree to verify the data consistency among validators
// TODO: I need to move these store functions from MockProtocolStorage to MockValidator. I have mistakenly put them in MockProtocolStorage
type MockProtocolStorage struct {
	store map[string]map[string][]byte
}

func (s *MockProtocolStorage) SetKeyRange(posi string, key_range [2]int64) {
	range_1_bytes := testhelper.Int64ToBytes(key_range[0])
	range_2_bytes := testhelper.Int64ToBytes(key_range[1])
	s.store[KEY_RANGE_STORE_KEY][posi] = append(range_1_bytes, range_2_bytes...)
}

func (s *MockProtocolStorage) CheckKeyRangeExist(posi string) bool {
	_, ok := s.store[KEY_RANGE_STORE_KEY][posi]
	return ok
}

func (s *MockProtocolStorage) GetKeyRange(posi string) [2]int64 {
	key_range_bytes := s.store[KEY_RANGE_STORE_KEY][posi]
	if len(key_range_bytes) == 0 {
		panic(fmt.Sprintf("Key range has not been set for validator %s, key_range_bytes = %v", posi, key_range_bytes))
	}
	range_1 := testhelper.BytesToInt64(key_range_bytes[:8])
	range_2 := testhelper.BytesToInt64(key_range_bytes[8:])

	return [2]int64{range_1, range_2}
}

func (s *MockProtocolStorage) IsKeyInRange(posi string, key int64) bool {
	key_range := s.GetKeyRange(posi)
	return key >= key_range[0] && key < key_range[1]
}

func (s *MockProtocolStorage) SetSecretShares(posi int64, key int64, scalar_bytes []byte) {
	s.store[SECRET_SHARES_STORE_KEY][strconv.FormatInt(posi, 10)+strconv.FormatInt(key, 10)] = scalar_bytes
}

func (s *MockProtocolStorage) GetSecretShares(posi int64, key int64) *btcec.ModNScalar {
	scalar_bytes := s.store[SECRET_SHARES_STORE_KEY][strconv.FormatInt(posi, 10)+strconv.FormatInt(key, 10)]
	scalar := new(btcec.ModNScalar)
	scalar.SetByteSlice(scalar_bytes)

	return scalar
}

func (s *MockProtocolStorage) SetLongTermSecretShares(key int64, scalar_bytes []byte) {
	s.store[LONG_TERM_SECRET_SHARES_KEY][strconv.FormatInt(key, 10)] = scalar_bytes
}

func (s *MockProtocolStorage) GetLongTermSecretShares(key int64) *btcec.ModNScalar {
	scalar_bytes := s.store[LONG_TERM_SECRET_SHARES_KEY][strconv.FormatInt(key, 10)]
	scalar := new(btcec.ModNScalar)
	scalar.SetByteSlice(scalar_bytes)

	return scalar
}

// go test -v -run ^TestPersistKeyRange$ github.com/nghuyenthevinh2000/bitcoin-playground/wsts
func TestPersistKeyRange(t *testing.T) {
	suite := testhelper.TestSuite{}
	suite.SetupStaticSimNetSuite(t)
	defer suite.StaticSimNetTearDown()

	storage := MockProtocolStorage{
		store: make(map[string]map[string][]byte),
	}

	storage.store[KEY_RANGE_STORE_KEY] = make(map[string][]byte)

	storage.SetKeyRange("1", [2]int64{10000, 20000})
	storage.SetKeyRange("2", [2]int64{20000, 30000})

	key_range := storage.GetKeyRange("1")
	assert.Equal(t, int64(10000), key_range[0])
	assert.Equal(t, int64(20000), key_range[1])

	key_range = storage.GetKeyRange("2")
	assert.Equal(t, int64(20000), key_range[0])
	assert.Equal(t, int64(30000), key_range[1])
}

// go test -v -run ^TestNewMockValidatorSet$ github.com/nghuyenthevinh2000/bitcoin-playground/wsts
func TestNewMockValidatorSet(t *testing.T) {
	suite := testhelper.TestSuite{}
	suite.SetupStaticSimNetSuite(t)
	defer suite.StaticSimNetTearDown()

	n := int64(4)
	n_keys := int64(10)
	threshold := int64(7)
	message_num := 10
	validators := make([]*MockValidator, n)
	for i := int64(0); i < n; i++ {
		frost := testhelper.NewFrostParticipant(&suite, n_keys, threshold, i+1, nil)

		validators[i] = NewMockValidator(&suite, frost, n, i+1)
	}

	deriveValidatorvp(&suite, validators)

	// peer discovery phase
	// validators will only exchange with one another through otherVals
	for i := int64(0); i < n; i++ {
		for j := int64(0); j < n; j++ {
			if i != j {
				validators[i].otherVals[j+1] = validators[j]
			}
		}
	}

	var wgGroup sync.WaitGroup
	// updating vp to all validators
	for i := int64(0); i < n; i++ {
		wgGroup.Add(1)
		go func(posi int64) {
			validators[posi].SendVPToAll()
			wgGroup.Done()
		}(i)
	}
	wgGroup.Wait()

	t.Logf("VPs have been updated")

	// key generation phase first round
	// each validator i sends (A_i, R_i, \mu_i) to all other validators
	for i := int64(0); i < n; i++ {
		wgGroup.Add(1)
		go func(posi int64) {
			validators[posi].DeriveAndSendProofs()
			wgGroup.Done()
		}(i)
	}
	wgGroup.Wait()

	t.Logf("Secret proofs have been sent")

	// key generation phase second round
	// each validator then sends secret shares to all other validators through secure, private channel
	for i := int64(0); i < n; i++ {
		wgGroup.Add(1)
		go func(posi int64) {
			validators[posi].DeriveAndSendSecretShares()
			wgGroup.Done()
		}(i)
	}
	wgGroup.Wait()

	t.Logf("Secret shares have been sent")

	// signing phase
	// each validator will prepare nonce commitments and send to all other validators
	for i := int64(0); i < n; i++ {
		wgGroup.Add(1)
		go func(posi int64) {
			validators[posi].DeriveAndSendNonces()
			wgGroup.Done()
		}(i)
	}
	wgGroup.Wait()

	t.Logf("Nonce commitments have been sent")

	// users will submit requests to validators
	// for brevity, users will submit withdraw transactions to a bitcoin vault address
	// validators will then sign these transactions, producing signature adaptors
	message_list := generateMsgWithdrawList(&suite, message_num)

	for i := int64(0); i < n; i++ {
		wgGroup.Add(1)
		go func(posi int64) {
			msgStruct := &MsgBatchWithdraw{
				WithdrawBatch: message_list,
			}
			msgBytes, err := proto.Marshal(msgStruct)
			assert.NoError(t, err)

			validators[posi].SendMessageOnChain(append([]byte{MSG_WITHDRAW_BATCH}, msgBytes...))
			wgGroup.Done()
		}(i)
	}
	wgGroup.Wait()

	// each validator will derive and send signature adaptors to all other validators

	// stop all validators
	for i := int64(0); i < n; i++ {
		validators[i].Stop()
	}
}

func NewMockValidator(suite *testhelper.TestSuite, frost *testhelper.FrostParticipant, party_num, position int64) *MockValidator {
	priv := secp256k1.GenPrivKey()
	keyPair := suite.NewKeyPairFromBytes(priv.Bytes())

	path := fmt.Sprintf("../debug/validator_%d.log", position)
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	assert.NoError(suite.T, err)

	validator := &MockValidator{
		suite:     suite,
		logger:    log.New(file, "", log.LstdFlags),
		file:      file,
		keyPair:   keyPair,
		frost:     frost,
		party_num: party_num,
		otherVals: make(map[int64]ReceivableValidator),
		localStorage: MockProtocolStorage{
			store: make(map[string]map[string][]byte),
		},
		protocolStorage: MockProtocolStorage{
			store: make(map[string]map[string][]byte),
		},
		position:        position,
		msgChanOnChain:  make(chan []byte),
		msgChanOffChain: make(chan []byte),
	}

	// initialize protocol storage for vp
	validator.protocolStorage.store[VP_STORE_KEY] = make(map[string][]byte)

	// initialize protocol storage for key ranges
	validator.protocolStorage.store[KEY_RANGE_STORE_KEY] = make(map[string][]byte)

	// initialize protocol storage for transactions
	validator.protocolStorage.store[TRANSACTION_STORE_KEY] = make(map[string][]byte)

	// initialize local storage for secret shares from each validator
	validator.localStorage.store[SECRET_SHARES_STORE_KEY] = make(map[string][]byte)

	// initialize local storage for long term secret shares
	validator.localStorage.store[LONG_TERM_SECRET_SHARES_KEY] = make(map[string][]byte)

	go validator.ReceiveMessageOnChainLoop()
	go validator.ReceiveMessageOffChainLoop()

	return validator
}

// assign vp to all validators
// so that all validators have 100% voting power
func deriveValidatorvp(suite *testhelper.TestSuite, validators []*MockValidator) {
	randsource := rand.New(rand.NewSource(time.Now().UnixNano()))
	total := int64(0)
	validators_vp := make([]math.LegacyDec, len(validators))

	// assign number of shares to each validator
	for i := 0; i < len(validators); i++ {
		rand_vp := randsource.Int63n(1000000)
		total += rand_vp
		validators_vp[i] = math.LegacyNewDecFromInt(math.NewInt(rand_vp))
	}

	// determine vp for each validator
	totalInt := math.LegacyNewDecFromInt(math.NewInt(total))
	for i := 0; i < len(validators); i++ {
		validators_vp[i] = validators_vp[i].Quo(totalInt)
		validators[i].protocolStorage.store[VP_STORE_KEY][strconv.Itoa(i+1)] = vpToBytes(suite, validators_vp[i])
	}

	// verify that total vp is 100%
	calculatedVP := math.LegacyZeroDec()
	for i := 0; i < len(validators); i++ {
		calculatedVP = calculatedVP.Add(validators_vp[i])
	}
	assert.Equal(suite.T, int64(1), calculatedVP.RoundInt().Int64())
}

func bytesToVp(suite *testhelper.TestSuite, bytes []byte) *math.LegacyDec {
	dec := &math.LegacyDec{}
	err := dec.Unmarshal(bytes)
	assert.NoError(suite.T, err)

	return dec
}

func vpToBytes(suite *testhelper.TestSuite, vp math.LegacyDec) []byte {
	bytes, err := vp.Marshal()
	assert.NoError(suite.T, err)

	return bytes
}

func generateMsgWithdrawList(suite *testhelper.TestSuite, message_num int) []*MsgWithdraw {
	msgList := make([]*MsgWithdraw, message_num)
	for i := 0; i < message_num; i++ {
		// random amount
		amount := rand.Int63n(1000000000)
		// random address
		_, key_pair := suite.NewHDKeyPairFromSeed("")
		// p2tr pubkey
		addr_str := suite.ConvertPubKeyToTrAddress(key_pair.Pub)

		msgList[i] = &MsgWithdraw{
			Receiver: addr_str,
			Amount:   amount,
		}
	}

	return msgList
}
