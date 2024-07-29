package wsts

import (
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	cosmossecp "github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	"github.com/nghuyenthevinh2000/bitcoin-playground/testhelper"
	"github.com/stretchr/testify/assert"
)

// go test -v -run ^TestCosmosCompatibleKey$ github.com/nghuyenthevinh2000/bitcoin-playground/wsts
func TestCosmosCompatibleKey(t *testing.T) {
	suite := testhelper.TestSuite{}
	suite.SetupStaticSimNetSuite(t)
	defer suite.StaticSimNetTearDown()

	priv := cosmossecp.GenPrivKey()
	cosmosPubBytes := priv.PubKey().Bytes()
	btcPriv, btcPub := btcec.PrivKeyFromBytes(priv.Bytes())
	btcPrivBytes := btcPriv.Serialize()
	btcPubBytes := btcPub.SerializeCompressed()

	assert.Equal(t, btcPrivBytes, priv.Bytes())
	assert.Equal(t, btcPubBytes, cosmosPubBytes)
}
