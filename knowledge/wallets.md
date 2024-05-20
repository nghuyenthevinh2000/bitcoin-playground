# Wallet types

1. https://bitcoin.stackexchange.com/questions/120439/private-key-on-bitcoin-core
2. https://bitcoin.stackexchange.com/questions/118127/how-to-recover-and-sweep-p2pk-coins/118130#118130
3. https://bitcointalk.org/index.php?topic=5475186.0
4. https://bitcointalk.org/index.php?topic=5469585.0

## Legacy Wallets
Legacy wallets are the traditional type of wallets that Bitcoin Core has used since its inception. They are based on the original wallet design, which **uses a collection of private keys**.

1. Key Management: Legacy wallets manage individual keys that are either randomly generated or derived from a seed in a less structured manner (compared to hierarchical deterministic (HD) wallets). Each key is independent.

2. Address Types: Supports all types of Bitcoin addresses, including P2PKH (addresses that start with '1'), P2SH (addresses that start with '3'), and bech32 addresses for SegWit (addresses that start with 'bc1').

3. Deterministic and Non-Deterministic: **Early versions of legacy wallets were non-deterministic**, meaning they did not generate keys from a single seed. Modern implementations are often HD but still use the legacy format.

4. Backup Requirements: For non-HD legacy wallets, you **need to back up the wallet frequently as new keys are created continually**. HD wallets require a one-time backup of the seed phrase.

## Descriptor Wallets
Descriptor Wallets, a newer development, **use HD output descriptors to describe the addresses in the wallet**. This method provides a more structured and understandable framework for wallet management.

Later Bitcoin wallets began using deterministic wallets where all private keys are generated from a single seed value. These wallets only ever need to be backed up once for typical onchain use. However, if a user exports a single private key from one of these wallets and an attacker acquires that key plus some nonprivate data about the wallet, they can potentially derive any private key in the wallet—​allowing the attacker to steal all of the wallet funds. **Additionally, keys cannot be imported into deterministic wallets. This means almost no modern wallets support the ability to export or import an individual key.**

| Descriptor                                 | Explanation                                                                                                                                                    |
|--------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| pkh(02c6…9ee5)                             | P2PKH script for the provided public key                                                                                                                       |
| sh(multi(2,022f…2a01,03ac…ccbe))           | P2SH multisignature requiring two signatures corresponding to these two keys                                                                                   |
| pkh([d34db33f/44'/0'/0']xpub6ERA…RcEL/1/*) | P2PKH scripts for the BIP32 `d34db33f` with the extended public key (xpub) at the path `M/44'/0'/0'`, which is `xpub6ERA…RcEL`, using the keys at `M/1/*` of that xpub |

1. Output Descriptors: Descriptors provide a straightforward and declarative way to describe which addresses a wallet should be able to use. They define how keys should be derived for receiving or change addresses.

2. Simplifies Wallet Creation and Recovery: Since descriptors tell exactly how to derive all necessary addresses, they make creating and recovering wallets more consistent and less prone to errors.

3. Support for Diverse Script Types: Descriptor wallets can easily support various types of scripts and multisig configurations because descriptors are designed to explicitly state the script construction rules.

4. Backup Simplicity: Like HD wallets, a descriptor wallet typically only **requires you to back up the seed and the descriptor** itself. This seed and descriptor together are enough to recover all possible addresses.

## Key Differences
1. Flexibility in Script Handling: Descriptor wallets allow for greater flexibility in defining complex scripts, including multisig, SegWit, and custom scripts, through a uniform interface.

2. Backup and Recovery: Descriptor wallets provide a more robust and error-proof recovery process using descriptors and a seed, whereas legacy wallets may require multiple backups over time if they are not HD.

3. Compatibility: Legacy wallets have wide compatibility across various Bitcoin services and older software. Descriptor wallets, being relatively new, are progressively gaining support but are best used with software that understands descriptors.

4. Ease of Use: Descriptor wallets can be more user-friendly, especially for advanced users looking to create specific types of wallets or developers integrating wallets with systems that need to understand wallet structure from a high level.

## Transition to Descriptor Wallets
Bitcoin Core and other wallet software are increasingly supporting descriptor wallets because they offer a clear path toward using more sophisticated wallet features while maintaining backward compatibility and ease of use for basic wallet functions. The transition from legacy to descriptor wallets represents an evolution towards more precise and flexible wallet management in the Bitcoin ecosystem.