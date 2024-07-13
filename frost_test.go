package main

import "testing"

// this is a minimal FROST implementation for educational purposes
// an overview os its Schnorr signature:
// our setting has n = 7 participants, with threshold t = 5 participants
// go test -v -run ^TestSubsetTaprootMuSig$ github.com/nghuyenthevinh2000/bitcoin-playground
func TestFrost(t *testing.T) {
	suite := TestSuite{}
	suite.setupStaticSimNetSuite(t)

	// n := 7
	// thres := 5

	// 1.2: each participants exchange their shares with all others
}
