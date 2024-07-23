package wsts

import (
	"math/rand"
	"testing"
	"time"

	"cosmossdk.io/math"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	"github.com/gogo/protobuf/proto"
	"github.com/nghuyenthevinh2000/bitcoin-playground/testhelper"
	"github.com/stretchr/testify/assert"
)

const (
	vp_STORE_KEY = "vp"
)

var (
	MESSAGE_VP_TYPE = byte(0)
)

// abstract the validator interface to force all validators to exchange through sending messages only
type ReceivableValidator interface {
	ReceiveMessage(msg []byte)
}

type MockValidator struct {
	ReceivableValidator

	suite     *testhelper.TestSuite
	keyPair   testhelper.KeyPair
	vp        math.LegacyDec
	position  int
	frost     *testhelper.FrostParticipant
	otherVals []ReceivableValidator

	localStorage    MockprotocolStorage
	protocolStorage MockprotocolStorage
}

// first bytes denote type of message
func (v *MockValidator) ReceiveMessage(msg []byte) {
	msgType := msg[0]
	msgBytes := msg[1:]
	switch msgType {
	case MESSAGE_VP_TYPE:
		v.suite.T.Logf("Validator %d received vp message", v.position)
		msg := MsgUpdateVP{}
		err := proto.Unmarshal(msgBytes, &msg)
		assert.NoError(v.suite.T, err)
		v.protocolStorage.store[vp_STORE_KEY][string(rune(msg.Source))] = msg.Vp
	default:
		v.suite.T.Logf("Unknown message type: %d", msgType)
	}
}

// serving as mock on - chain storage in each mock validator
// and all validator need to have the same storage data
type MockprotocolStorage struct {
	store map[string]map[string][]byte
}

// go test -v -run ^TestNewMockValidatorSet$ github.com/nghuyenthevinh2000/bitcoin-playground/wsts
func TestNewMockValidatorSet(t *testing.T) {
	suite := testhelper.TestSuite{}
	suite.SetupStaticSimNetSuite(t)

	n := 100
	threshold := 67
	validators := make([]*MockValidator, n)
	for i := 0; i < n; i++ {
		frost := testhelper.NewFrostParticipant(&suite, n, threshold, nil)

		validators[i] = NewMockValidator(&suite, frost, i+1)
	}

	deriveValidatorvp(validators)
	for i := 0; i < n; i++ {
		t.Logf("Validator %d has vp: %s", i, validators[i].vp.String())
	}

	// peer discovery phase
	// validators will only exchange with one another through otherVals
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			if i != j {
				validators[i].otherVals = append(validators[i].otherVals, validators[j])
			}
		}
	}

	// key generation phase first round
	// each validator sends (

	// key generation phase second round
}

func NewMockValidator(suite *testhelper.TestSuite, frost *testhelper.FrostParticipant, position int) *MockValidator {
	priv := secp256k1.GenPrivKey()
	keyPair := suite.NewKeyPairFromBytes(priv.Bytes())

	validator := &MockValidator{
		suite:   suite,
		keyPair: keyPair,
		frost:   frost,
		localStorage: MockprotocolStorage{
			store: make(map[string]map[string][]byte),
		},
		protocolStorage: MockprotocolStorage{
			store: make(map[string]map[string][]byte),
		},
		position: position,
	}

	// initialize protocol storage for vp
	validator.protocolStorage.store[vp_STORE_KEY] = make(map[string][]byte)

	return validator
}

// assign vp to all validators
// so that all validators have 100% voting power
func deriveValidatorvp(validators []*MockValidator) {
	randsource := rand.New(rand.NewSource(time.Now().UnixNano()))
	total := int64(0)

	// assign number of shares to each validator
	for i := 0; i < len(validators); i++ {
		rand_vp := randsource.Int63n(1000000)
		total += rand_vp
		validators[i].vp = math.LegacyNewDecFromInt(math.NewInt(rand_vp))
	}

	// determine vp for each validator
	totalInt := math.LegacyNewDecFromInt(math.NewInt(total))
	percentage := math.LegacyNewDecFromInt(math.NewInt(100))
	for i := 0; i < len(validators); i++ {
		validators[i].vp = validators[i].vp.Quo(totalInt)
		validators[i].vp = validators[i].vp.Mul(percentage)
	}
}

func bytesToVp(bytes []byte) *math.LegacyDec {
	dec := &math.LegacyDec{}
	err := dec.Unmarshal(bytes)
	if err != nil {
		dec = nil
	}

	return dec
}
