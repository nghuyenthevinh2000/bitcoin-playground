# BIP0143 - SigHash for SegWit

the SIGHASH flag determines which parts of the transaction are signed and thus protected from modification
* SIGHASH_ALL: This is the default flag. The signature commits to all inputs and outputs in the transaction
* SIGHASH_NONE: The signature commits to all inputs, but not to any outputs. This allows the outputs to be changed without invalidating the signature.
* SIGHASH_SINGLE: The signature commits to all inputs and the corresponding output (by index) in the transaction. If there is no corresponding output, the signature is invalid. This allows other outputs to be changed without invalidating the signature.
* SIGHASH_ANYONECANPAY: The signature only commits to the single input it is attached to and not to the other inputs. This allows other inputs to be added or removed without invalidating the signature. SIGHASH_ANYONECANPAY can be combined with the three others:
    * SIGHASH_ALL | SIGHASH_ANYONECANPAY
    * SIGHASH_NONE | SIGHASH_ANYONECANPAY
    * SIGHASH_SINGLE | SIGHASH_ANYONECANPAY

Schnorr signature 65 bytes composition:
* public nonces (R): 32 bytes
* signature (s): 32 bytes
* sighash flag: 1 bytes

## 1. Fixing Transaction Malleability
Transaction malleability is an issue where the transaction ID (TxID) of a transaction can be altered without changing the underlying transaction's details (inputs and outputs). This can be problematic because:
* It allows third parties to alter the transaction in a way that changes its ID but not its contents, potentially disrupting the transaction tracking.
* It complicates building layers on top of Bitcoin, such as payment channels or multi-signature wallets, which rely on stable transaction IDs.

BIP0143 addresses this by segregating the witness data (signatures) from the transaction data, thus ensuring that any changes to the signature do not affect the transaction ID.

## 2. Improving Efficiency
The original sighash algorithm required hashing large parts of the transaction multiple times, which was computationally expensive and inefficient. BIP0143 introduces a new sighash algorithm that:

Optimizes the data included in the signature hash, reducing the computational load.
Avoids unnecessary rehashing of parts of the transaction that do not change between inputs, improving overall performance.

## 3. Supporting Segregated Witness (SegWit)
Segregated Witness (SegWit) is a major upgrade to the Bitcoin protocol that:

Separates the transaction's signature data from its other data, allowing for larger blocks and increasing transaction throughput.
Changes the transaction format to allow for future upgrades and features without hard forks.
The new signature hashing method proposed in BIP0143 is a fundamental part of SegWit, enabling the separation of signature data and making the protocol more flexible and efficient.

## 4. Enhanced Security and Flexibility
The new signature hashing scheme introduced by BIP0143 enhances security by:

Ensuring that only the necessary parts of the transaction are included in the signature hash, reducing the attack surface.
Making it easier to implement advanced features such as Schnorr signatures and Taproot in the future, which can further improve security and privacy.

## 5. Backward Compatibility
BIP0143 and SegWit are designed to be backward-compatible, meaning that they can be introduced without disrupting the existing Bitcoin network. This ensures a smooth transition and allows users and developers to adopt the new features at their own pace.