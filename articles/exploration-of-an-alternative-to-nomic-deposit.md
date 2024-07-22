# Exploration of an alternative to Nomic user deposit
This article introduces a better model for security and improved user deposit UX

## How Nomic user deposit currently works?
The Nomic user deposit script is not an atomic swap, thus putting user at risk of losing their BTC without receiving anything yet. This can be improved using Point-Time-Lock-Contract and weighted threshold Schnorr adaptor signatures.

```
1. Key Path: Aggregated public key composed of base signatory set (largest 2/3 of signatory set by voting power)
2. Script Paths:
* Fallback script - Weighted multisig containing all signatory public keys and voting power
* Deposit address commitment - An OP_RETURN to indicate where the pegged BTC should be credited on the sidechain
* Deposit reclamation script - Must be signed by depositor, only valid after timelock has passed
```

The current design requires user to deposit BTC first into the Nomic validator set address. Upon approved, Nomic validator set will mint bridged BTC to user address on Nomic network. The only safety mechanism here is user ability to crawl back funds after some locktime. However, Nomic validator set already has the upperhand of holding the money in their hands and can send it to another address before the timelock matured.

HTLC is a famous Bitcoin native contract used in atomic swap. PTLC is a Schnorr version of HTLC with smaller footprint, and privacy - preserving. When combined with [weighted threshold Schnorr adaptor signatures](https://www.mdpi.com/2079-9292/13/1/76), the PTLC is further secured with PoS. The scheme ensures that user will either receive their bridged BTC, or the swap falls off.