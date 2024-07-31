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
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	"github.com/nghuyenthevinh2000/bitcoin-playground/testhelper"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
)

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

// go test -v -run ^TestPersistKeyRange$ github.com/nghuyenthevinh2000/bitcoin-playground/wsts
func TestPersistKeyRange(t *testing.T) {
	suite := testhelper.TestSuite{}
	suite.SetupStaticSimNetSuite(t)

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

	n := int64(4)
	n_keys := int64(10)
	threshold := int64(7)
	message_num := 10
	validators := make([]*MockValidator, n)
	for i := int64(0); i < n; i++ {
		path := fmt.Sprintf("../debug/validator_%d.log", i+1)
		file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		assert.NoError(suite.T, err)
		logger := log.New(file, "", log.LstdFlags)

		frost := testhelper.NewFrostParticipant(&suite, logger, n_keys, threshold, i+1, nil)

		validators[i] = NewMockValidator(&suite, logger, file, frost, n, i+1)
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

	time_now := time.Now()
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
	t.Logf("VPs have been updated, finished in %v", time.Since(time_now))

	// key generation phase first round
	// each validator i sends (A_i, R_i, \mu_i) to all other validators
	time_now = time.Now()
	for i := int64(0); i < n; i++ {
		wgGroup.Add(1)
		go func(posi int64) {
			validators[posi].DeriveAndSendProofs()
			wgGroup.Done()
		}(i)
	}
	wgGroup.Wait()
	t.Logf("Secret proofs have been sent, finished in %v", time.Since(time_now))

	// key generation phase second round
	// each validator then sends secret shares to all other validators through secure, private channel
	time_now = time.Now()
	for i := int64(0); i < n; i++ {
		wgGroup.Add(1)
		go func(posi int64) {
			validators[posi].DeriveAndSendSecretShares()
			wgGroup.Done()
		}(i)
	}
	wgGroup.Wait()

	// probing to see if all validators have GroupPublicKey
	validators_with_group_pubkey := make(map[int64]bool)
	for {
		missing_list := make([]int64, 0)
		for i := int64(0); i < n; i++ {
			if _, ok := validators_with_group_pubkey[i]; !ok {
				if validators[i].frost.GroupPublicKey != nil {
					validators_with_group_pubkey[i] = true
				} else {
					missing_list = append(missing_list, i+1)
				}
			}
		}

		if len(missing_list) < 10 {
			t.Logf("Validators missing GroupPublicKey: %v", missing_list)
		} else {
			t.Logf("num of validators missing GroupPublicKey: %d", len(missing_list))
		}

		if len(validators_with_group_pubkey) == int(n) {
			break
		}

		time.Sleep(3 * time.Second)
	}
	t.Logf("Secret shares have been sent, finished in %v", time.Since(time_now))

	// transition between two phases
	// set mock genesis btc checkpoint for the protocol
	trScript, err := txscript.PayToTaprootScript(validators[0].frost.GroupPublicKey)
	assert.NoError(suite.T, err)
	first_tx := suite.NewMockFirstTx(trScript, 1000000000)
	tx_out_index := uint32(0)
	suite.UtxoViewpoint.AddTxOut(btcutil.NewTx(first_tx), tx_out_index, 0)
	for i := int64(0); i < n; i++ {
		validators[i].MockSetGenesisCheckPoint(first_tx, tx_out_index)
	}

	// signing phase
	// each validator will prepare nonce commitments and send to all other validators
	time_now = time.Now()
	for i := int64(0); i < n; i++ {
		wgGroup.Add(1)
		go func(posi int64) {
			validators[posi].DeriveAndSendNonces()
			wgGroup.Done()
		}(i)
	}
	wgGroup.Wait()

	t.Logf("Nonce commitments have been sent, finished in %v", time.Since(time_now))

	// users will submit requests to validators
	// for brevity, users will submit withdraw transactions to a bitcoin vault address
	// validators will then sign these transactions, producing signature adaptors
	time_now = time.Now()
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

	t.Logf("Withdraw messages have been sent, finished in %v", time.Since(time_now))

	// each validator will derive and send signature adaptors to all other validators
	// in a production environment, validators are honest all the time, except for some rare cases
	// this scheme protects against those rare cases
	time_now = time.Now()
	for i := int64(0); i < n; i++ {
		wgGroup.Add(1)
		go func(posi int64) {
			retry_time := 5
			for retry_time > 0 {
				err := validators[posi].DeriveTxAndSign()
				if err == nil {
					break
				}
				t.Logf("retry signing for validator %d", posi)
				retry_time--
				time.Sleep(3 * time.Second)
			}
			wgGroup.Done()
		}(i)
	}
	wgGroup.Wait()

	t.Logf("Done signing in %v", time.Since(time_now))

	// stop all validators
	for i := int64(0); i < n; i++ {
		validators[i].Stop()
	}
}

func NewMockValidator(suite *testhelper.TestSuite, logger *log.Logger, file *os.File, frost *testhelper.FrostParticipant, party_num, position int64) *MockValidator {
	priv := secp256k1.GenPrivKey()
	keyPair := suite.NewKeyPairFromBytes(priv.Bytes())

	validator := &MockValidator{
		suite:         suite,
		logger:        logger,
		file:          file,
		keyPair:       keyPair,
		frost:         frost,
		partyNum:      party_num,
		btcGasFee:     1000,
		otherVals:     make(map[int64]ReceivableValidator),
		dishonestVals: make(map[int64]bool),
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

	// initialize protocol storage for Bitcoin chain checkpoint
	validator.protocolStorage.store[CHECKPOINT_STORE_KEY] = make(map[string][]byte)

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
		amount := rand.Int63n(1000000)
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
