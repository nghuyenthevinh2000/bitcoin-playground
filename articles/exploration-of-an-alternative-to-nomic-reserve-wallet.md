# Exploration of an alternative to Nomic reserve wallet
This article introduces a better model for security and bridge UX to Nomic reserve wallet.

The Nomic reserve wallet is currently secured by a weighted threshold signature script. This has a large footprint on the network for each added signer, leading to a linear increase in gas fees and making it difficult to scale security. This can be improved using weighted threshold Schnorr signatures, which have a constant-sized Bitcoin footprint of 16 vB, regardless of the number of signers.

## How Nomic reserve wallet security currently works?
Nomic proposes a secure reserve wallet script allowing a PoS weighted validator set to manage its's Bitcoin reserve. However, the security is somewhat compromised between key path spend and fallback script. For key path, we have non - weighted n-of-n MuSig2 signing on Bitcoin from the largest 2-of-3 of Nomic validator set. If one validator is down, then fallback script is used. Fallback script will have to reveal all validator signatures, then accumulate VP for any valid signatures to pass threshold. The on - chain witness can be: 16*n + 10*n vB. The calculation bases on signature size of 16vB, and a block script for VP valuation of 10vB.

Assume that n = 100, with 4sats/vB, a checkpoint in every Bitcoin block can cost 7\$/block, 1000\$/day, 30000\$/month. This is considering low gas fee and not during Ordinals, Rune hype.

```
1. Key Path: Aggregated public key composed of base signatory set (largest 2/3 of signatory set by voting power)
2. Script Paths:
* Fallback script - Weighted multisig containing all signatory public keys and voting power
```

Looking at two Nomic consecutive checkpoints: 
1. Block 853277: [transaction](https://mempool.space/tx/271724ed465f269c5067ed8d8206bddf7bad740eee6d00541756416ad1d74841). It costed 2.38\$ for 683 vB with fallback script of 20 signers in witness
2. Block 853322: [transaction](https://mempool.space/tx/a205091d77fd9ff31ec58262609592dec865f9b3f28c986f5e769d3364f7df45). It costed 2.51\$ for 811.5 vB with fallback script of 20 signers in witness

Two checkpoints are 45 blocks (8 hours) apart. Meaning that people received their bridged Bitcoin in 8 hours.

Thus, if there is an alternative with smaller on - chain footprint, less gas is paid, more frequent checkpoints, better bridge UX. By leveraging weighted threshold Schnorr signatures, we can achieve both constant cheap gas fees and scalable security.

## Proposed architecture
This architecture suggests how to implement the concepts from this paper to Cosmos: https://trust-machines.github.io/wsts/wsts.pdf.

Each validator has a signing party managing a number of "virtual keys" and participates in a weighted threshold Schnorr signature. The total number of signing parties is denoted as $N_p$, while the total number of keys is denoted as $N_k$. In the setting of a normal Tendermint protocol, there would be around 100 validators, equivalent to $N_p = 100$. The total number of keys $N_k$ can be determined by governance. For example, if there are 5000 keys, they will be proportionately managed by each party based on their voting power.

As long as there is a threshold-passing number of keys provided, the Bitcoin script will be unlocked to move to the next checkpoint.

Each validator i generates one persistent party polynomial $f_i(x) = a_{i0} + a_{i1}x + a_{i2}x^2 + \ldots + a_{it}x^t$, with t as 2-of-3 threshold of $N_k$.

## Key generation phase
A key generation phase is invoked if there is a significant shift in voting power that leads to a change in key composition. Preferably keeping the VP stable to avoid invoking key generation.

1. In round 1, each validator calculate:
   * secret shares for all keys: $f_i(k), i \in \{1, \ldots, N_p\}, k \in \{1, \ldots, N_k\}$
   * polynomial coefficient commitments: $A_i=\{g^{a_{i0}}, g^{a_{i1}}, ..., g^{a_{it}}\}$
   * secret proofs for $a_{i0}$: $(R_i, \mu_i)$

    They then submit on - chain $(A, R_i, \mu_i)$ for others to verify.

2. In round 2, validator i propagates securely secret shares $(i, (k, f_i(k)))$ to the corresponding party managing key k. 

    Parties verify the received secret shares against the public on-chain commitments $A_i$. Once verified, the secret signing key $s_k$ will be derived, and held privately. Else, k will be eliminated from the signing for the next Bitcoin checkpoint. Aggregated public key P is derived from aggregating $A_{i0}, i \in \{1, \ldots, N_p\}$.

    Validators base on the latest VP table to expect the number of secret shares from others. If some validators provide more than expected, they can hi - jack the multi-signature. Thus, this action will result in slash. Potentially tombstoned.

    A local process is needed to handle the management and distribution of secret shares.

## Signing phase
Signing phase is invoked for any new Bitcoin reserve wallet checkpoint

1. In round 1, each validators generate party nonce pairs (d, e) and submit nonce commitments on - chain $(D_i, E_i)$.

2. In round 2, each validator independently derives the next PSBTs based on last UTXOs, aggregated public key P and transactions to be processed. They will then independently calculate their partial signature $z_i$ and submit it on - chain.
   * provided that more than 2/3 of validators are honest, the full Schnorr signature can be derived and be submitted to Bitcoin by anyone, verifiable by the Bitcoin miners. The signature is privacy - preserving and tamper - proof.
   * otherwise, if more than 1/3 of validators are Byzantine, the full Schnorr signature cannot be derived due to not having enough satisfied points for the Lagrange interpolation. Thus, this deters any Byzantine behaviors.