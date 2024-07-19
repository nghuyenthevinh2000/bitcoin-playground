# bitcoin-playground
playground to mess around with bitcoin scripts

1. learn-btc-script: https://github.com/supertestnet/learn-btc-script
2. mastering bitcoin 3rd edition: https://github.com/bitcoinbook/bitcoinbook
3. debug tool: https://github.com/bitcoin-core/btcdeb

# current direction
This repository goal is to find and quickly test ideas about Bitcoin products and solutions. Why the author is dedicated to this goal? Bitcoin is the most trusted and decentralized blockchain. It has neither foundations nor major controlling parties. But, Bitcoin is not Turing - complete and prohibitively expensive in gas for any serious applications. This frustration has forced a group of people to leave and build Etherum, Solana, .... While the rest remains to find ways around the limitations. The so called "Script Renaissance" is finally possible now with Taproot on Bitcoin mainnet, with promises of greatly enhanced script expressiveness squeezable into a constant - sized Schnorr signature. It is time to return and find new riches!

![one piece](knowledge/assets/going_merry.webp)

# Bitcoin building blocks
A Bitcoin product will consist of many building blocks. Here is a list of discovered building blocks so far in Bitcoin. For any readers out there, please help me complete my knowledge gap so I can one day come up with a new solution and onboard you to our pirate ship 😎😎😎

My contact: nghuyenthevinh@gmail.com

I am also trying to understand deeply by rebuilding POC for these building blocks

## adaptor signatures
Adaptor signature is regarded as one of the native contract on Bitcoin. It uses secret pre - images as conditions for a Bitcoin payment. If conditions are satisfied, pre - images are revealed thus fulfilling a Bitcoin payment.

In its simplest form, blockchain transactions involve sending tokens from A to B under certain conditions. On Ethereum, these conditions are programmable and enforced on-chain. On Bitcoin, conditions exist in the form of signatures, which provide insufficient expressiveness for smart contracts. However, signatures can be split into many partial ones and can only be recreated if all components are provided. This allows A to hide secrets behind some off-chain conditions, which are then revealed to B for full signature creation once A's conditions are satisfied. This approach is called "adaptor signatures."

The management of secret pre - images often fall upon one party. If it is between Alice and Bob, then no big deal. If it is managed by a centralized oracle, then collusion with bad actors can easily happen.

There are many adaptor signatures proposed so far:
1. [HTLC](https://bitcoinops.org/en/topics/htlc/)
2. [PTLC](https://bitcoinops.org/en/topics/ptlc/)
3. [DLC](https://github.com/aljazceru/discreet-log-contracts)
4. [Hedgehog](https://github.com/supertestnet/hedgehog)
5. [Threshold adaptor signatures](https://www.mdpi.com/2079-9292/13/1/76)

## multi - signatures
Multi-signature is undoubtedly one of the most important building blocks for Bitcoin script authorization. It minimizes trust among all involved participants. When combined with economic incentives to punish dishonest participants and reward honest ones, we have Proof-of-Stake.

In the past, scaling signers in a multi-signature scheme was challenging because each new signer increased the script size, leading to prohibitively expensive gas prices. Taproot and Schnorr introduce multiple ways to create multi-signatures with minimal on-chain footprint, making it relatively cheap to support a large number of signers.

Here are the proposed multi - signature schemes:
1. [OP_CHECKMULTISIG (SegWit v0)](https://en.bitcoin.it/wiki/OP_CHECKMULTISIG)
2. [OP_CHECKSIGADD (SegWit v1)](https://en.bitcoin.it/wiki/BIP_0342)
3. [MuSig2](https://eprint.iacr.org/2020/1261.pdf)
4. [Frost](https://glossary.blockstream.com/frost/)
5. [Weighted multi - signature](https://gist.github.com/mappum/da11e37f4e90891642a52621594d03f6)

## transaction chaining
Transaction chaining provides a great way to interlock conditional UTXOs. In its most primitive form, an off-chain UTXO refers to an on-chain output, which is then followed by another off-chain UTXO. Settlement can be done by submitting all chained off - chain UTXOs. From this primitive form, there are three forms of chaining:
* 1 out (1 UTXO) - 1 in (1 UTXO): An input refers to an output. Settlement requires submitting that output and input on-chain.
* 2 out (2 UTXOs) - 2 in (1 UTXO): Two inputs in one UTXO refer to two different outputs, held by two different parties. Settlement requires both parties to submit their outputs asynchronously, then the input.
* 2 out (1 UTXO) - 2 in (2 UTXOs): Two inputs in two different UTXOs refer to two outputs in the same UTXO. Settlement can be done independently by each party by submitting the first UTXO with two inputs, then their respective input.

Transaction chaining allows participants to control the flow of UTXOs based on a certain set of pre - defined conditions. More details are needed as I delve into this kind of building block.

1. [Ark connector outputs](https://ark-protocol.org/intro/connectors/index.html): tree - form connectors
2. [CPFP](https://bitcoinops.org/en/topics/cpfp/): simple fee - bumping technique

## data inscription
Data inscription allows writing abitrary data onto a Bitcoin block, attested by the Bitcoin miners. This is a great way to store any off - chain protocol data onto the Bitcoin, and later retrieved for any off - chain protocol execution, or verification. However, the Bitcoin miners only attest that the protocol data exists on - chain at this specific timestamp, not verifying whether the data is honest. The honesty relies on the protocol security model, and public participants.

Perharps, this is the most commonly talked about section. RGB only publishes a signature attesting to the off - chain data, so it is much worse than Ordinals which store the whole data. However, both protocol publisher remains centralized and thus prone to attacks. If an attacker manages to take over the protocol publisher, and colludes with all clients to reward them, then unlimited amount of money can be printed.

This solution group relies on `OP_RETURN`

1. [RGB: single-use seal](https://docs.rgb.info/distributed-computing-concepts/single-use-seals)
2. [Ordinals](https://docs.ordinals.com/)