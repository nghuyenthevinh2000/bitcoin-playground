package main

import (
	"bufio"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

const (
	MockBtcdHost  = "localhost:18556"
	MockBtcUser   = "regtest"
	MockBtcPass   = "regtest"
	MockBlockTime = 3 * time.Second
	MiningAddress = "sb1qu8rtzymwzkyk5rfewwczt6hgq8sjxssuhrmw7w"

	MockWalletHost = "localhost:18554"
	MockWalletPass = "vinh"
)

// managing bitcoin regtest process
type RegBitcoinProcess struct {
	Cmd *exec.Cmd
}

func (reg *RegBitcoinProcess) RunBitcoinProcess(genBlock bool) {
	// setup bitcoin node running in regtest mode
	rpcUser := fmt.Sprintf("--rpcuser=%s", MockBtcUser)
	rpcPass := fmt.Sprintf("--rpcpass=%s", MockBtcPass)
	reg.Cmd = exec.Command("btcd", "--simnet", "--txindex", "--notls", "-b", "simnet/btcd", "--logdir", "simnet/btcd/logs", "--miningaddr", MiningAddress, rpcUser, rpcPass, "&")
	// set child process group id to the same as parent process id, so that KILL signal can kill both parent and child processes
	reg.Cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	// determine if there is already a running btcd process
	if !isProcessRunning("btcd") {
		if err := reg.Cmd.Start(); err != nil {
			panic(err)
		}
	} else {
		fmt.Println("btcd process already running")
	}

	// wait for bitcoin node to start
	time.Sleep(5 * time.Second)

	// generate blocks
	// if newly created bitcoin regtest, need to generate 101 blocks to finalize coinbase rewards. This is for insufficient funds
	if genBlock {
		go func() {
			for {
				err := exec.Command("btcctl", "--simnet", "--notls", rpcUser, rpcPass, "generate", "1").Run()
				if err != nil {
					panic(err)
				}
				time.Sleep(MockBlockTime)
			}
		}()
	}
}

func (reg *RegBitcoinProcess) Stop() {
	if reg.Cmd != nil && reg.Cmd.Process != nil {
		err := reg.Cmd.Process.Kill()
		if err != nil {
			panic(err)
		}
	}
}

func (reg *RegBitcoinProcess) LogError() {
	stderr, _ := reg.Cmd.StderrPipe()
	scanner := bufio.NewScanner(stderr)
	for scanner.Scan() {
		fmt.Println(scanner.Text())
	}
}

func isProcessRunning(name string) bool {
	cmd := exec.Command("pgrep", name)
	out, err := cmd.Output()

	if err != nil {
		fmt.Printf("Error: %v", err)
		return false
	}

	if len(strings.TrimSpace(string(out))) == 0 {
		return false
	}

	return true
}
