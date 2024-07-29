# Types of transactions

## Transaction version
Bitcoin transactions have undergone several version updates since its inception. Here are the main transaction versions:

1. Version 1: 
    The original version introduced with Bitcoin's initial release.

2. Version 2:
    Introduced with BIP 68, BIP 112, and BIP 113 to support relative locktime (BIP 68) and CHECKSEQUENCEVERIFY (BIP 112).

3. Version 3:
    Proposed in BIP 141 (Segregated Witness), although not widely used in practice.

4. Version 4:
    Also proposed in BIP 141, intended for future extensions but similarly not widely used.
    These versions reflect the evolution of Bitcoin's protocol to include more advanced features and improve security and flexibility.

## CoinBase transaction
CoinBase transaction rewards miners with BTC, it has no inputs, only outputs to successful miners

## SegWit transaction
1. SegWit program:
* A version byte: 1 bytes
* A witness program: 2 - 40 bytes