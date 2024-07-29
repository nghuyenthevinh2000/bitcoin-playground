# BTCD

btcd is the main provider of Bitcoin go library

1. start a btcd process: `btcd --simnet --txindex -P regtest -u regtest --notls -b simnet/btcd --logdir=simnet/btcd/logs --miningaddr=sb1qu8rtzymwzkyk5rfewwczt6hgq8sjxssuhrmw7w`
2. interact with btcd process: `btcctl --simnet -P regtest -u regtest --notls getblockchaininfo`
3. start a btcwallet process to interact with btcd: `btcwallet --noclienttls --noservertls -A simnet/walletdb --simnet --btcdusername=regtest --btcdpassword=regtest -u regtest -P regtest`
4. interact with btcwallet process: `btcctl --simnet -P regtest -u regtest --notls --wallet getinfo`

## bitcoin-cli useful commands
1. bitcoin-cli generatetoaddress 101 bcrt1q2r5a8jsveqj98lcqyjy9vl08j6tfgtzfwvfnx4
2. bitcoin-cli getblock 76a065259466589d16404628afb3339657d3090268fb39aac0cbd84e88392e13
3. bitcoin-cli gettransaction 50e16f494eecbd723783c900c81cc93a48e540bc099a7f8361c37dbbb7cff913 false true
4. bitcoin-cli sendtoaddress bcrt1q2r5a8jsveqj98lcqyjy9vl08j6tfgtzfwvfnx4 1
5. bitcoin-cli listunspent 1 9999999 '["bcrt1q2r5a8jsveqj98lcqyjy9vl08j6tfgtzfwvfnx4"]'
6. bitcoin-cli listwallets
* for setting up wallets in bitcoin core
7. bitcoin-cli -rpcwallet=alice -generate 100

## btcd Useful commands
1. list all commands: `btcctl --regtest -P regtest -u regtest -s 0.0.0.0:18443 --notls getblockchaininfo -l`
2. create a new wallet: `btcwallet -c localhost:18556 --noclienttls --noservertls -A simnet/walletdb --simnet --btcdusername=regtest --btcdpassword=regtest -u regtest -P regtest --create`
3. a list of btcwallet supported commands: https://github.com/btcsuite/btcwallet/blob/master/rpc/legacyrpc/methods.go#L60
4. generate blocks (after defining --miningaddr in btcd): btcctl --simnet -P regtest -u regtest --notls generate 101

#### setup an account to receive funds
1. unlock wallet: `btcctl --simnet -P regtest -u regtest --notls --wallet walletpassphrase vinh 60`
2. create new account: `btcctl --simnet -P regtest -u regtest --notls --wallet createnewaccount vinh`
3. generate new receiving address: `btcctl --simnet -P regtest -u regtest --notls --wallet getnewaddress vinh bech32`
4. list accounts: `btcctl --simnet -P regtest -u regtest --notls --wallet listaccounts`
5. check total balances: `btcctl --simnet -P regtest -u regtest --notls --wallet getbalance`
6. check all spendable UTXOs: `btcctl --simnet -P regtest -u regtest --notls --wallet listunspent`
7. send: `btcctl --simnet -P regtest -u regtest --notls --wallet sendtoaddress`

## test suite
1. chainSetup(): helps setup a mock chain in btcd, should explore this more