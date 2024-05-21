# BTCD

btcd is the main provider of Bitcoin go library

1. start a btcd process: `btcd --simnet --txindex -P regtest -u regtest --notls -b simnet/btcd --logdir=simnet/btcd/logs --miningaddr=sb1qu8rtzymwzkyk5rfewwczt6hgq8sjxssuhrmw7w`
2. interact with btcd process: `btcctl --simnet -P regtest -u regtest --notls getblockchaininfo`
3. start a btcwallet process to interact with btcd: `btcwallet -c localhost:18556 --noclienttls --noservertls -A simnet/walletdb --simnet --btcdusername=regtest --btcdpassword=regtest -u regtest -P regtest`
4. interact with btcwallet process: `btcctl --simnet -P regtest -u regtest --notls --wallet getinfo`

## Useful commands
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