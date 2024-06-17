package main

import "testing"

func TestDLC(t *testing.T) {
	s := TestSuite{}
	s.setupSuite(t)

	// setup alice and bob
	// _, alice_pub, alice_priv := s.generateKeyPair()
	// _, bob_pub, bob_priv := s.generateKeyPair()

}

// a DLC channel is a multisig channel between alice and bob
// preferred model is 2/2 MuSig2
func (s *TestSuite) createChannel() {

}
