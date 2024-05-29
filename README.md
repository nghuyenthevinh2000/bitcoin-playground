# bitcoin-playground
playground to mess around with bitcoin scripts

1. learn-btc-script: https://github.com/supertestnet/learn-btc-script
2. mastering bitcoin 3rd edition: https://github.com/bitcoinbook/bitcoinbook
3. debug tool: https://github.com/bitcoin-core/btcdeb

## a list of useful bitcoin-cli commands
1. bitcoin-cli generatetoaddress 101 bcrt1q2r5a8jsveqj98lcqyjy9vl08j6tfgtzfwvfnx4
2. bitcoin-cli getblock 76a065259466589d16404628afb3339657d3090268fb39aac0cbd84e88392e13
3. bitcoin-cli gettransaction 50e16f494eecbd723783c900c81cc93a48e540bc099a7f8361c37dbbb7cff913 false true
4. bitcoin-cli sendtoaddress bcrt1q2r5a8jsveqj98lcqyjy9vl08j6tfgtzfwvfnx4 1
5. bitcoin-cli listunspent 1 9999999 '["bcrt1q2r5a8jsveqj98lcqyjy9vl08j6tfgtzfwvfnx4"]'
6. bitcoin-cli listwallets
* for setting up wallets in bitcoin core
7. bitcoin-cli -rpcwallet=alice -generate 100

## bitcoin-cli wallet
1. there are two types of bitcoin wallets
* Legacy wallets (traditional non-descriptor wallets)
* Descriptor wallets

2. bitcoin-cli requires importing wallet to query, else it won't. Upon import, it will scan the whole network for that wallet UTXOs. Preferably using preset wallets for test cases.
3. create wallet
* check knowledge/btcd.md