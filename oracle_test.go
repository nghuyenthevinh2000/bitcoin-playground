package main

import "testing"

// witness - execution oracle test

// TestWitnessSignature
// send funds from execution oracle to another address
// execution oracle should not be able to execute the transaction without the witness signature
func TestWitnessSignature(t *testing.T) {
	s := TestSuite{}
	s.setupSuite(t)

	// create a set of 2/3 multisig as witness oracle
	// setup alice wallet as execution oracle

	// witness created and announced

	//
}
