package wsts

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/nghuyenthevinh2000/bitcoin-playground/testhelper"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
)

const (
	// protocol storage
	VP_STORE_KEY                       = "vp"
	KEY_RANGE_STORE_KEY                = "key_range"
	NONCE_COMMITMENTS_STORE_KEY        = "nonce_commitments"
	TRANSACTION_STORE_KEY              = "transactions"
	CHECKPOINT_STORE_KEY               = "checkpoint"
	PUBLIC_NONCE_COMMITMENTS_STORE_KEY = "public_nonce_commitments"
	ADAPT_SIG_STORE_KEY                = "adapt_sig"

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
	MSG_UPDATE_ADAPT_SIG         = byte(6)
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

	suite               *testhelper.TestSuite
	logger              *log.Logger
	file                *os.File
	keyPair             testhelper.KeyPair
	position            int64
	partyNum            int64
	frost               *testhelper.FrostParticipant
	otherVals           map[int64]ReceivableValidator
	dishonestVals       map[int64]bool
	btcGasFee           int64
	btcCheckpointheight int64

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
			v.logger.Printf("Received on - chain message type: %d\n", msgType)
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
				v.logger.Printf("received nonce commitments from source: %d, with num of nonces: %d\n", msg.Source, len(msg.NonceCommitments))

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
			case MSG_UPDATE_ADAPT_SIG:
				// MSG_UPDATE_ADAPT_SIG can be called when all nonces have not yet been added in the previous phase
				// need to ensure that there are group public nonce commitments before entering this phase
				signing_index := int64(0)
				if v.frost.AggrNonceCommitment[signing_index] == nil {
					v.logger.Println("received MSG_UPDATE_ADAPT_SIG but nil AggrNonceCommitment")
					go func() {
						time.Sleep(1000)
						v.msgChanOnChain <- msg
					}()
					break
				}

				msg := &MsgUpdateAdaptSig{}
				err := proto.Unmarshal(msgBytes, msg)
				assert.NoError(v.suite.T, err)
				enough_honest := v.partyNum - int64(len(v.dishonestVals))
				// verify adapt sig
				adapt_sig, err := schnorr.ParseSignature(msg.AdaptSig)
				assert.NoError(v.suite.T, err)
				if legit := v.verifyAdaptSig(msg.Source, 0, adapt_sig); !legit {
					v.logger.Printf("validator %d is dishonest with adapt sig: %v\n", msg.Source, adapt_sig)
					v.dishonestVals[msg.Source] = true
					break
				}
				// save adapt sig
				v.storeAdaptSig(0, msg.Source, msg.AdaptSig)
				// check if enough adapt sigs have been received
				// if enough, then verifiy and signal transaction ready to be broadcasted
				if v.isEnoughAdaptSig(0, enough_honest) {
					v.handleFinalizeTransaction()
				}
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
			v.logger.Printf("Received off - chain message type: %d\n", msgType)
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
				// range_key * partyNum
				range_key := v.protocolStorage.GetKeyRange(strconv.FormatInt(v.position, 10))
				total_keys := (range_key[1] - range_key[0]) * v.partyNum
				accumulated_keys := int64(len(v.localStorage.store[SECRET_SHARES_STORE_KEY]))
				v.logger.Printf("validator %d needs more keys %d\n", v.position, total_keys-accumulated_keys)
				if accumulated_keys == total_keys && v.frost.GroupPublicKey == nil {
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

	polynomialCommitmentsBytes := make([][]byte, v.frost.Threshold+1)
	for i := int64(0); i <= v.frost.Threshold; i++ {
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

	// self - sending in case this validator has collected all secret shares before finishing itself thus unable to activate the check
	// check if this validator has received all secret shares
	secretShareMsg := MsgSecretShares{
		Source:       v.position,
		SecretShares: make([]*SecretShares, 0),
	}
	secretShareMsgBytes, err := proto.Marshal(&secretShareMsg)
	assert.NoError(v.suite.T, err)
	v.SendMessageOffChain(append([]byte{MSG_SECRET_SHARES}, secretShareMsgBytes...))
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
		_, err = v.getNonceCommitments(v.position, int64(i))
		assert.NoError(v.suite.T, err)
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

func (v *MockValidator) DeriveTxAndSign() error {
	// derive bitcoin transactions
	hType := txscript.SigHashDefault
	sigHash, _ := v.handleTxs(hType)

	// derive honest validators
	honest := make([]int64, 0)
	honest_keys := make([]int64, 0)
	for i := int64(1); i <= v.partyNum; i++ {
		if _, ok := v.dishonestVals[i]; !ok {
			honest = append(honest, i)
			key_range := v.protocolStorage.GetKeyRange(strconv.FormatInt(i, 10))
			for j := key_range[0]; j < key_range[1]; j++ {
				honest_keys = append(honest_keys, j)
			}
		}
	}

	// derive public nonce commitments
	signing_index := int64(0)
	public_nonces := make(map[int64][2]*btcec.PublicKey)
	for _, i := range honest {
		nonceCommitments, err := v.getNonceCommitments(i, signing_index)
		if err != nil {
			return err
		}

		public_nonces[i] = nonceCommitments
	}

	public_nonce_commitments := v.frost.CalculatePublicNonceCommitments(signing_index, honest, sigHash, public_nonces)

	// derive signature adaptors
	key_range := v.protocolStorage.GetKeyRange(strconv.FormatInt(v.position, 10))
	signing_shares := make(map[int64]*btcec.ModNScalar)
	for i := key_range[0]; i < key_range[1]; i++ {
		signing_shares[i] = v.GetLongTermSecretShares(i)
	}

	adapt_sig := v.frost.WeightedPartialSign(v.position, signing_index, honest, honest_keys, sigHash, public_nonces, signing_shares)

	// self - verified
	if legit := v.verifyAdaptSig(v.position, signing_index, adapt_sig); !legit {
		v.logger.Printf("self - verification failed")
		return fmt.Errorf("validator %d: self - verification failed", v.position)
	}

	// store public nonce commitments and adapt sig
	v.storePublicNonceCommitments(signing_index, public_nonce_commitments)
	v.storeAdaptSig(signing_index, v.position, adapt_sig.Serialize())

	// send adapt sig to all other validators
	for _, otherVal := range v.otherVals {
		msg := MsgUpdateAdaptSig{
			Source:   v.position,
			AdaptSig: adapt_sig.Serialize(),
		}

		msgBytes, err := proto.Marshal(&msg)
		assert.NoError(v.suite.T, err)

		otherVal.SendMessageOnChain(append([]byte{MSG_UPDATE_ADAPT_SIG}, msgBytes...))
	}

	return nil
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
	if party_keys[1] < 0 {
		panic("party 1 has negative amount of keys")
	}

	// remove temporary add
	delete(v.otherVals, v.position)

	// derive range of keys for each party
	range_keys := make(map[int64][2]int64)
	start := int64(1)
	for i := int64(1); i <= v.partyNum; i++ {
		end := start + party_keys[i]
		range_keys[i] = [2]int64{start, end}
		start = end
	}
	assert.Equal(v.suite.T, v.partyNum, int64(len(range_keys)))

	return range_keys
}

func (v *MockValidator) verifyAdaptSig(posi, signing_index int64, adapt_sig *schnorr.Signature) bool {
	// verify adapt sig
	// adapt sig is verified by all validators
	// if all validators agree, then the transaction is ready to be broadcasted
	// if not, then the transaction is invalid
	hType := txscript.SigHashDefault
	sigHash, _ := v.handleTxs(hType)

	honest_keys := make([]int64, 0)
	for i := int64(1); i <= v.partyNum; i++ {
		if _, ok := v.dishonestVals[i]; !ok {
			key_range := v.protocolStorage.GetKeyRange(strconv.FormatInt(i, 10))
			for j := key_range[0]; j < key_range[1]; j++ {
				honest_keys = append(honest_keys, j)
			}
		}
	}

	key_range := v.protocolStorage.GetKeyRange(strconv.FormatInt(posi, 10))
	public_signing_share := make(map[int64]*btcec.PublicKey)
	for i := key_range[0]; i < key_range[1]; i++ {
		public_signing_share[i] = v.frost.PublicSigningShares[i]
	}

	return v.frost.WeightedPartialVerification(adapt_sig, signing_index, posi, sigHash, honest_keys, public_signing_share)
}

func (v *MockValidator) verifySharesAndCalculateLongTermKey() {
	// extract secret shares of a key from all validators
	time_now := time.Now()
	key_range := v.protocolStorage.GetKeyRange(strconv.FormatInt(v.position, 10))

	v.frost.DerivePowerMap()

	var wg sync.WaitGroup
	for i := key_range[0]; i < key_range[1]; i++ {
		wg.Add(1)
		go func(i int64) {
			all_secret_shares := make(map[int64]*btcec.ModNScalar)
			for j := int64(1); j <= v.partyNum; j++ {
				all_secret_shares[j] = v.localStorage.GetSecretShares(j, i)
			}

			v.frost.VerifyBatchPublicSecretShares(all_secret_shares, uint32(i))

			longTermShares := new(btcec.ModNScalar)
			longTermShares.SetInt(0)
			for j := int64(1); j <= v.partyNum; j++ {
				longTermShares.Add(all_secret_shares[j])
			}
			longTermSharesBytes := longTermShares.Bytes()
			v.SetLongTermSecretShares(i, longTermSharesBytes[:])

			// calculate public signing shares
			key := v.frost.CalculateInternalPublicSigningShares(longTermShares, i)
			v.logger.Printf("key %d, long term key: %v\n", i, key)
			wg.Done()
		}(i)
	}
	wg.Wait()
	v.logger.Printf("Time to verify secret shares: %v\n", time.Since(time_now))

	// calculate public signing shares of all others
	time_now = time.Now()
	for i := int64(1); i <= v.partyNum; i++ {
		if i == v.position {
			continue
		}
		var wg sync.WaitGroup
		key_range := v.protocolStorage.GetKeyRange(strconv.FormatInt(i, 10))
		for j := key_range[0]; j < key_range[1]; j++ {
			wg.Add(1)
			go func(j int64) {
				key := v.frost.CalculatePublicSigningShares(v.partyNum, j)
				v.logger.Printf("for validator %d, key %d, long term key: %v\n", i, j, key)
				wg.Done()
			}(j)
		}
		wg.Wait()
	}
	v.logger.Printf("Time to calculate public signing shares: %v\n", time.Since(time_now))

	// calculate group public key
	groupkey := v.frost.CalculateGroupPublicKey(v.partyNum)
	v.logger.Printf("group public key: %v\n", groupkey)
}

// txs will affect this network next inputs, and outputs
// there should be one transaction for each check point
// store it in the protocol storage for future sign
//
// return sighash for further signing process
func (v *MockValidator) handleTxs(hType txscript.SigHashType) ([32]byte, *wire.MsgTx) {
	// get previous checkpoint from storage
	prev_checkpoint := v.getBtcCheckPoint(v.btcCheckpointheight - 1)
	v.logger.Printf("prev checkpoint: %v\n", prev_checkpoint)
	checkpoint_hash, err := chainhash.NewHashFromStr(prev_checkpoint.OutHash)
	assert.NoError(v.suite.T, err)

	// get prevout
	prev_out := wire.OutPoint{
		Hash:  *checkpoint_hash,
		Index: prev_checkpoint.OutIndex,
	}
	prev_tx_out := v.suite.UtxoViewpoint.FetchPrevOutput(prev_out)
	vault_balance := prev_tx_out.Value

	// construct new tx for this checkpoint height
	btc_tx := wire.NewMsgTx(2)
	btc_tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: prev_out,
	})

	outputs := make([]*wire.TxOut, 0)
	for _, tx := range v.getAllTxs() {
		vault_balance -= tx.Amount
		assert.GreaterOrEqual(v.suite.T, vault_balance, int64(0))

		addr, err := btcutil.DecodeAddress(tx.Receiver, v.suite.BtcdChainConfig)
		assert.NoError(v.suite.T, err)

		txOut := &wire.TxOut{
			Value:    tx.Amount,
			PkScript: addr.ScriptAddress(),
		}
		outputs = append(outputs, txOut)
	}

	// add next checkpoint output
	group_key := v.frost.GroupPublicKey
	trScript, err := txscript.PayToTaprootScript(group_key)
	assert.NoError(v.suite.T, err)

	// include fees
	vault_balance -= v.btcGasFee
	assert.GreaterOrEqual(v.suite.T, vault_balance, int64(0))

	checkpoint_out := &wire.TxOut{
		Value:    vault_balance,
		PkScript: trScript,
	}
	outputs = append([]*wire.TxOut{checkpoint_out}, outputs...)

	for _, txOut := range outputs {
		btc_tx.AddTxOut(txOut)
	}

	// calculating sighash
	inputFetcher := txscript.NewCannedPrevOutputFetcher(
		prev_tx_out.PkScript,
		prev_tx_out.Value,
	)
	sigHashes := txscript.NewTxSigHashes(btc_tx, inputFetcher)
	sigHash, err := txscript.CalcTaprootSignatureHash(sigHashes, hType, btc_tx, 0, inputFetcher)
	assert.Nil(v.suite.T, err)

	return ([32]byte)(sigHash), btc_tx
}

func (v *MockValidator) handleFinalizeTransaction() {
	honest := make([]int64, 0)
	for i := int64(1); i <= v.partyNum; i++ {
		if _, ok := v.dishonestVals[i]; !ok {
			honest = append(honest, i)
		}
	}

	z := new(btcec.ModNScalar)
	for _, party := range honest {
		adapt_sig := v.getAdaptSig(0, party)
		z_i := new(btcec.ModNScalar)
		z_i.SetByteSlice(adapt_sig.Serialize()[32:64])
		z.Add(z_i)
	}

	// sending the transaction with the final signature
	prev_checkpoint := v.getBtcCheckPoint(v.btcCheckpointheight - 1)
	checkpoint_hash, err := chainhash.NewHashFromStr(prev_checkpoint.OutHash)
	assert.NoError(v.suite.T, err)

	// get prevout
	prev_out := wire.OutPoint{
		Hash:  *checkpoint_hash,
		Index: prev_checkpoint.OutIndex,
	}
	prev_tx_out := v.suite.UtxoViewpoint.FetchPrevOutput(prev_out)
	inputFetcher := txscript.NewCannedPrevOutputFetcher(
		prev_tx_out.PkScript,
		prev_tx_out.Value,
	)

	hType := txscript.SigHashDefault
	_, btc_tx := v.handleTxs(hType)
	v.suite.HashCache.AddSigHashes(btc_tx, inputFetcher)

	err = blockchain.ValidateTransactionScripts(
		btcutil.NewTx(btc_tx), v.suite.UtxoViewpoint, txscript.StandardVerifyFlags, v.suite.SigCache, v.suite.HashCache,
	)
	assert.Nil(v.suite.T, err)
}

func (v *MockValidator) SetLongTermSecretShares(key int64, scalar_bytes []byte) {
	v.localStorage.store[LONG_TERM_SECRET_SHARES_KEY][strconv.FormatInt(key, 10)] = scalar_bytes
}

func (v *MockValidator) GetLongTermSecretShares(key int64) *btcec.ModNScalar {
	scalar_bytes := v.localStorage.store[LONG_TERM_SECRET_SHARES_KEY][strconv.FormatInt(key, 10)]
	scalar := new(btcec.ModNScalar)
	scalar.SetByteSlice(scalar_bytes)

	return scalar
}

func (v *MockValidator) storePolyCommitments(posi int64, commitments [][]byte) {
	var err error
	poly_commitments := make([]*btcec.PublicKey, v.frost.Threshold+1)
	for i := int64(0); i <= v.frost.Threshold; i++ {
		poly_commitments[i], err = btcec.ParsePubKey(commitments[i])
		assert.NoError(v.suite.T, err)
	}
	v.frost.UpdatePolynomialCommitments(posi, poly_commitments)
}

func (v *MockValidator) getPolyCommitments(posi int64) []*btcec.PublicKey {
	return v.frost.PolynomialCommitments[posi]
}

func (v *MockValidator) storeBtcCheckPoint(checkpoint_height int64, checkpoint *BtcCheckPoint) {
	checkpointBytes, err := proto.Marshal(checkpoint)
	assert.NoError(v.suite.T, err)
	v.protocolStorage.store[CHECKPOINT_STORE_KEY][strconv.FormatInt(checkpoint_height, 10)] = checkpointBytes
}

func (v *MockValidator) getBtcCheckPoint(checkpoint_height int64) *BtcCheckPoint {
	checkpointBytes := v.protocolStorage.store[CHECKPOINT_STORE_KEY][strconv.FormatInt(checkpoint_height, 10)]
	checkpoint := &BtcCheckPoint{}
	err := proto.Unmarshal(checkpointBytes, checkpoint)
	assert.NoError(v.suite.T, err)
	return checkpoint
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
	// check if substore exists
	if _, ok := v.protocolStorage.store[substore_key]; !ok {
		v.protocolStorage.store[substore_key] = make(map[string][]byte)
	}
	v.protocolStorage.store[substore_key][strconv.FormatInt(posi, 10)] = commitments
}

func (v *MockValidator) getNonceCommitments(posi, signing_index int64) ([2]*btcec.PublicKey, error) {
	substore_key := NONCE_COMMITMENTS_STORE_KEY + strconv.FormatInt(signing_index, 10)
	commitment_bytes := v.protocolStorage.store[substore_key][strconv.FormatInt(posi, 10)]
	commitment := &NonceCommitments{}
	err := proto.Unmarshal(commitment_bytes, commitment)
	if err != nil {
		return [2]*btcec.PublicKey{}, err
	}

	D, err := btcec.ParsePubKey(commitment.D)
	if err != nil {
		v.logger.Printf("error parsing D for signing index: %d, posi: %d\n", signing_index, posi)
		return [2]*btcec.PublicKey{}, err
	}

	E, err := btcec.ParsePubKey(commitment.E)
	if err != nil {
		v.logger.Printf("error parsing E for signing index: %d, posi: %d\n", signing_index, posi)
		return [2]*btcec.PublicKey{}, err
	}

	return [2]*btcec.PublicKey{D, E}, nil
}

func (v *MockValidator) storePublicNonceCommitments(signing_index int64, public_nonce_commitments map[int64]*btcec.PublicKey) {
	substore_key := PUBLIC_NONCE_COMMITMENTS_STORE_KEY + strconv.FormatInt(signing_index, 10)
	v.protocolStorage.store[substore_key] = make(map[string][]byte)
	for posi, commitment := range public_nonce_commitments {
		v.protocolStorage.store[substore_key][strconv.FormatInt(posi, 10)] = commitment.SerializeCompressed()
	}
}

func (v *MockValidator) getPublicNonceCommitments(signing_index int64) map[int64]*btcec.PublicKey {
	substore_key := PUBLIC_NONCE_COMMITMENTS_STORE_KEY + strconv.FormatInt(signing_index, 10)
	commitments := make(map[int64]*btcec.PublicKey)
	for posi, commitment_bytes := range v.protocolStorage.store[substore_key] {
		pubkey, err := btcec.ParsePubKey(commitment_bytes)
		assert.NoError(v.suite.T, err)
		posi_int, err := strconv.ParseInt(posi, 10, 64)
		assert.NoError(v.suite.T, err)
		commitments[posi_int] = pubkey
	}

	return commitments
}

func (v *MockValidator) storeAdaptSig(signing_index, posi int64, adapt_sig []byte) {
	substore_key := ADAPT_SIG_STORE_KEY + strconv.FormatInt(signing_index, 10)
	v.protocolStorage.store[substore_key] = make(map[string][]byte)
	v.protocolStorage.store[substore_key][strconv.FormatInt(posi, 10)] = adapt_sig
}

func (v *MockValidator) getAdaptSig(signing_index, posi int64) *schnorr.Signature {
	substore_key := ADAPT_SIG_STORE_KEY + strconv.FormatInt(signing_index, 10)
	adapt_sig_bytes := v.protocolStorage.store[substore_key][strconv.FormatInt(posi, 10)]
	adapt_sig, err := schnorr.ParseSignature(adapt_sig_bytes)
	assert.NoError(v.suite.T, err)

	return adapt_sig
}

func (v *MockValidator) isEnoughAdaptSig(signing_index, honest_num int64) bool {
	substore_key := ADAPT_SIG_STORE_KEY + strconv.FormatInt(signing_index, 10)
	return int64(len(v.protocolStorage.store[substore_key])) == honest_num
}

// mock set checkpoint at btc block height = 0 for testing
func (v *MockValidator) MockSetGenesisCheckPoint(first_tx *wire.MsgTx, tx_out_index uint32) {
	// save genesis checkpoint
	checkpoint := &BtcCheckPoint{
		OutHash:  first_tx.TxHash().String(),
		OutIndex: tx_out_index,
	}
	v.storeBtcCheckPoint(0, checkpoint)
	v.btcCheckpointheight = 1
}
