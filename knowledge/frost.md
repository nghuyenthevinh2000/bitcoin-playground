# FROST
source: https://eprint.iacr.org/2020/852.pdf

Today is 13/07/2024, I will successfully code a demo implementation of FROST - Flexible Round Optimizationed Schnorr Theshold Signatures

The code: [here](../musig_test.go)

# Additions to DKG
The goal of FROST is to apply VSS into a Schnorr scheme for it to work. Here are the proposed building blocks:
1. Additive secret sharing: While Shamir secret sharing and derived constructions require shares to be points on a secret polynomial f where f(0) = s, an additive secret sharing scheme allows a set of $\alpha$ participants to jointly compute a shared secret s by each participant $P_{i}$ contributing a value $s_{i}$ such that the resulting shared secret is $s = \sum_{i=1}^{\alpha} s_i$, the summation of each participant’s share.
2. DKG: Unlike threshold schemes such as Shamir secret sharing that rely on a trusted dealer, Distributed Key Generation (DKG) ensures every participant contributes equally to the generation of the shared secret. At the end of running the protocol, all participants share a joint public key Y , but each participant holds only a share si of the corresponding secret s such that no set of participants smaller than the threshold knows s
3. Schnorr signature

## Mentioned attacks (todo, not yet understood)
1. Attack via Wagner’s Algorithm
2. Attack via ROS Solver
3. Rogue - key attacks

## FROST Architecture
1. Efficiency over Robustness: Robustness here means that if the number of Byzantine participants is less than the threshold then the honest others can still complete the protocol. However, in settings where one can expect misbehaving participants to be rare, threshold signing protocols can be relaxed to be more efficient in the “optimistic” case that all participants honestly follow the protocol. In the case that a participant does misbehave, honest participants can identify the misbehaving participant and abort the protocol, and then re-run the protocol after excluding the misbehaving participant. FROST **trades off robustness in the protocol for improved two round efficiency** in this way.
2. Signature Aggregator Role: We instantiate FROST using a semi-trusted signature aggregator role, denoted as SA. Such a role allows for less communication overhead between signers and is often practical in a real-world setting.