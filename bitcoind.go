package main

import (
	"fmt"
	"os/exec"
	"syscall"
	"time"
)

const (
	MockBtcHost   = "localhost:18443"
	MockBtcUser   = "regtest"
	MockBtcPass   = "regtest"
	MockBlockTime = 3 * time.Second
)

// managing bitcoin regtest process
type RegBitcoinProcess struct {
	Cmd *exec.Cmd
}

func (reg *RegBitcoinProcess) RunBitcoinProcess() {
	// setup bitcoin node running in regtest mode
	rpcUser := fmt.Sprintf("-rpcuser=%s", MockBtcUser)
	rpcPass := fmt.Sprintf("-rpcpassword=%s", MockBtcPass)
	reg.Cmd = exec.Command("bitcoind", "-regtest", "-fallbackfee=0.0000001", "-listen", "-server", "-rpcport=18443", rpcUser, rpcPass)
	// set child process group id to the same as parent process id, so that KILL signal can kill both parent and child processes
	reg.Cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}
	err := reg.Cmd.Start()
	if err != nil {
		panic(err)
	}

	// wait for bitcoin node to start
	time.Sleep(5 * time.Second)

	// generate blocks
	// if newly created bitcoin regtest, need to generate 101 blocks to finalize coinbase rewards. This is for insufficient funds
	go func() {
		for {
			err := exec.Command("bitcoin-cli", "-rpcwallet=alice", "-regtest", "-generate", "-rpcport=18443", rpcUser, rpcPass).Run()
			if err != nil {
				panic(err)
			}
			time.Sleep(MockBlockTime)
		}
	}()
}

func (reg *RegBitcoinProcess) Stop() {
	if reg.Cmd != nil && reg.Cmd.Process != nil {
		err := reg.Cmd.Process.Kill()
		if err != nil {
			panic(err)
		}
	}
}
