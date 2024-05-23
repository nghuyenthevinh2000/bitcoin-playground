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
	MiningAddress = "Sg3XPraEoadWBBcw4C7cDSDpmi1tymxqPX"

	MockWalletHost = "localhost:18554"
	MockWalletPass = "vinh"
)

// managing bitcoin regtest process
type RegBitcoinProcess struct {
	BitcoinCmd *exec.Cmd
	WalletCmd  *exec.Cmd
}

func (reg *RegBitcoinProcess) RunWalletProcess() {
	// setup wallet running in simnet mode
	reg.WalletCmd = exec.Command("btcwallet", "--simnet", "--noclienttls", "--noservertls", "-A", "simnet/walletdb", "--btcdusername", MockBtcUser, "--btcdpassword", MockBtcPass, "-u", MockBtcUser, "-P", MockBtcPass, "&")
	// set child process group id to the same as parent process id, so that KILL signal can kill both parent and child processes
	reg.WalletCmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	// determine if there is already a running btcwallet process
	if !isProcessRunning("btcwallet") {
		if err := reg.WalletCmd.Start(); err != nil {
			panic(err)
		}
	} else {
		fmt.Println("btcwallet process already running")
	}

	// wait for wallet to start
	time.Sleep(3 * time.Second)
}

func (reg *RegBitcoinProcess) StopWallet() {
	if reg.WalletCmd != nil && reg.WalletCmd.Process != nil {
		err := reg.WalletCmd.Process.Kill()
		if err != nil {
			panic(err)
		}
	}
}

func (reg *RegBitcoinProcess) LogWalletError() {
	stderr, _ := reg.WalletCmd.StderrPipe()
	scanner := bufio.NewScanner(stderr)
	for scanner.Scan() {
		fmt.Println(scanner.Text())
	}
}

func (reg *RegBitcoinProcess) RunBitcoinProcess(genBlock bool) {
	// setup bitcoin node running in simnet mode
	rpcUser := fmt.Sprintf("--rpcuser=%s", MockBtcUser)
	rpcPass := fmt.Sprintf("--rpcpass=%s", MockBtcPass)
	reg.BitcoinCmd = exec.Command("btcd", "--simnet", "--txindex", "--notls", "-b", "simnet/btcd", "--logdir", "simnet/btcd/logs", "--miningaddr", MiningAddress, rpcUser, rpcPass, "&")
	// set child process group id to the same as parent process id, so that KILL signal can kill both parent and child processes
	reg.BitcoinCmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	// determine if there is already a running btcd process
	if !isProcessRunning("btcd") {
		if err := reg.BitcoinCmd.Start(); err != nil {
			panic(err)
		}
	} else {
		fmt.Println("btcd process already running")
	}

	// wait for bitcoin node to start
	time.Sleep(3 * time.Second)

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

func (reg *RegBitcoinProcess) StopBitcoin() {
	if reg.BitcoinCmd != nil && reg.BitcoinCmd.Process != nil {
		err := reg.BitcoinCmd.Process.Kill()
		if err != nil {
			panic(err)
		}
	}
}

func (reg *RegBitcoinProcess) LogBitcoinError() {
	stderr, _ := reg.BitcoinCmd.StderrPipe()
	scanner := bufio.NewScanner(stderr)
	for scanner.Scan() {
		fmt.Println(scanner.Text())
	}
}

func isProcessRunning(name string) bool {
	cmd := exec.Command("pgrep", name)
	out, err := cmd.Output()

	if err != nil {
		return false
	}

	if len(strings.TrimSpace(string(out))) == 0 {
		return false
	}

	return true
}
