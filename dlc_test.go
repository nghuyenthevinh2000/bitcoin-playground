package main

import (
	"log"
	"testing"

	"github.com/nghuyenthevinh2000/bitcoin-playground/testhelper"
)

func TestDLC(t *testing.T) {
	s := testhelper.TestSuite{}
	s.SetupSimNetSuite(t, log.Default())

	// setup alice and bob
	// _, alice_pub, alice_priv := s.generateKeyPair()
	// _, bob_pub, bob_priv := s.generateKeyPair()

}
