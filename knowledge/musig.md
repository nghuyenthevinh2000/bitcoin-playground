# MuSig

1. Source:
* https://colab.research.google.com/github/bitcoinops/taproot-workshop/blob/Colab/1.2-musig.ipynb
* https://www.youtube.com/watch?v=5MbTptrXEC4
* https://eprint.iacr.org/2018/068

2. MuSig key notes
Using a signature aggregation scheme like MuSig has two significant advantages over using Script's `OP_CHECKMULTISIG` and tapscript's `OP_CHECKSIGADD` opcodes
* **Transaction Size/Fees**: an aggregate MuSig pubkey and signature is indistinguishable from a single-key pubkey and signature, meaning that the transaction size (and required fee) for a multi-key output are the same as for a single-key output.
* **Privacy and Fungibility**: an aggregate MuSig pubkey and signature is indistinguishable from a single-key pubkey and signature, making it impossible for anyone to use the public block chain data to identify where a multi-key scheme has been used.

BIP340 is linear in the nonce points and public keys, which means that public keys, nonces and signatures can be aggregated.

To counter the key cancellation attack, each participant's pubkey is tweaked by **a challenge factor**.

**PERSONAL RECOMMENDATION**: reader should spend 1 hour to figure out how this challenge factor can help safe guard against key cancellation attack.

