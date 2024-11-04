[!info]
> How do we do multi signature ?  
> 
> Says, Alice and Bob have some funds locked in a simple 2-of-2 multisig contract 
> - Alice knows the adaptor point $Y = y  \times G$
> - Wants to give Bob the adaptor signature, which he can use to claim funds if he learn the adaptor secret $y$
> - Bob, then use $y$ to decrypt the signature, and publish then transaction 


# On-chain (Legacy) 

## [[ESCSA ]] on chain siging

Simplest way is to use `OP_CHECKMULTISIG` opcode:
- Sign and submit ECDSA signatures from the selection of keys hardcoded into the locking script 

## Adaptor signature 
 Example
- Alice signs whatever transaction she wants to lock behind the adaptor point $Y$
- Forward the transaction to Bob (not broadcasting it)
- Bobs uses $y$ to decrypt the signature, publish the transaction 
- Alice identifies it on blockchain, learn $y$

# Off-chain  (Mordern)

- With support of [[Schnorr]], signature created by aggregation appear to be normal Schnorr Signature:
- Completely indistinct from signatures created by solo-signers 

# General concept 

>Think of it like: no matter which multi-sig scheme you use, the core idea is the same - adapt the combined nonce before creating the challenge hash, and everyone must do this together.


# MuSig1

Let's walk through an example signing session with MuSig1 to find out how an adaptor signature is created with MuSig.


## Setup 

Let $b$ be Bob's secret key, with corresponding public key $P_b = k_b \times G$

### Key aggregation 
📢 Public:

 Alice and Bob compute their aggregated public key $D$:

   $L = \{P_a, P_b\}$
   
   $\alpha_a = H_{agg}(L \parallel P_a)$    $\alpha_b = H_{agg}(L \parallel P_b)$
   
  `^agk` $P = \alpha_a \times P_a + \alpha_b \times P_b$ ^7fdf51
  
  >[!note]  $/alpha$ is the weighted parameter
  
### Nonce phase 
🔒  Alice and Bob sample their random nonces:

   $r_a \leftarrow \mathbb{Z}_n$    $r_b \leftarrow \mathbb{Z}_n$

📢. Alice and Bob compute their public nonces:

   $R_a = r_a \times G$    $R_b = r_b \times G$
   
   $\hat{R} = R_a + R_b$

📢. Alice and Bob send each other their nonce commitments:

   $t_a = H_{com}(R_a)$    $t_b = H_{com}(R_b)$

📢.  Once they have received each other's commitments, Alice and Bob send each other their nonces $R_a$ and $R_b$.

### Message agreement
📢. Alice and Bob agree on a message $m$ to sign.

## Apply adaptor 

📢. Alice and Bob can independently compute their public nonce $\hat{R}$
   
   $\hat{R} = R_a + R_b$
   
   Then, adapt it: 
   $R = \hat{R} + Y$

Compute the hash challenge 
   
   $e = H_{sig}(R || P || m)$  

	   - $P$ is the aggregated pubic key

🔒. Partial sign 

	 $s_a = r_a + ek_a \alpha_a$
	 $s_b = r_b + ek_b\alpha_b$
	 
	 $\hat{s} = s_a + s_b$
	
📢. Get the final adapter signature, 

     $R = \hat{R} + Y$
     $s = \hat{s} + y$
## Verification

>[!note] Verifying the signature 
>
> $sG= R + e \times P$
> 	 = $\hat{R} + Y + e \times P$
> 	 = $R_a + R_b + Y + e \times D$
> 	 = $r_a \times G  + r_b \times G + y \times G + e \times (\alpha_a k_a + \alpha_b k_a) \times G$    ([[#^7fdf51]])
> 	 = $(r_a + ek_a\alpha_a + r_b + ek_b\alpha_b + y) \times G$
> 	 = $(s_a + s_b  + y) \times G$
> 	 = $(\hat{s} + y) \times G$



## Free Option problem 

>[!warning] whichever party shares their partial signature first might lose the ability to learn the adaptor secret $y$

For example,
- Alice has $y$, sign partially and give $Y$ to Bob
- if Alice send $s_a$ first to Bob.
- Bob refuse to give $s_b$ to Alice
- Wait to learn $y$ 

## Use Cases

1. Alice and Bob have a `multi-sig wallet`
2. Should be only <mark> valid if some condition is met </mark>

### Without adaptor 
- The final signature needs `y` to be valid 
- Transaction can't be published without $y$
- Acts as a <mark> conditional lock </mark> on the multi-signature 


>[!important] 
>The key point is adaptor signatures add conditionality to MuSig1 - allowing the multi-signature to be valid only when some condition (knowledge of y) is met.


# Multi-Adaptors

> [!info] what if we want a single adaptor signature, to require:
> - both secrets $y1, y2$
> - Either secrets 

## `AND` case 

This is simple, we can just aggregate two secret together:

- $y' = y_1 + y_2$
- $Y_1 = y_1 \times G$       $Y_2 = y_2 \times G$
- $Y' = Y_1 + Y2$

$Y_1$ and $Y2$ are shared, Alice and Bob can then construct an `AS` using $Y'$ 

## `OR` case 

As the signature bearer, Alice knows the relationship $y' = y_1 + y2$

<mark> Bob generates a hint $z$,  which he can give to Alice. </mark> Then, he computes it:

$z = y_2 - y_1$

Alice can receives $z$, then verify that Bob computed it correctly:

$zG = Y_2 - Y_1$
= $y_2 \times G - y_1 \times G$
= $(y_2 - y_1) \times G$

Now, Alice learns $y$, she can use the hint $z$ to compute the full adaptor secret $y'$ by solving the equation 

$z = y_2 - y_1$


# Revocation 

Consider a situation
- Bob and Alice jointly signed a transaction 
- Signature is adapted with the point $Y$ 
- Bob knows $y$ 
- Alice aware that 

>[!warning] Are there a way, for Bob to convince Alice that he will not broadcast the tx? 


## Revocation Mechanism
 1. Problem: 
 - Old states shouldn't be published 
 - Need way to punish if old state is published 
 
 2. Solution: 
- Bob gives Alice a "revocation key" 
- If Bob publishes (reveals y) 
- Alice can use revealed y + revocation key 
- Alice can then take ALL funds as punishment

## Key Exposure Threat 

>[!warning] What if Bob has no money in the first place? Bob can not be punished if he has nothing available to forfeit 
>

We still can punish Bob if he commits to exposing: his `private key`

### How to reveal the private key 
#### Revealing the nonce 

Considering the simple [[Schnorr]] signature $(R, s)$, where $s = r + ek$

>[!warning] if we are given $(R, s)$, and the secret nonce $r$, we can compute $k$
>
> $s = r + ek$
> $s - r = ek$
> $e^{-1} (s -r) = k$




>[!important] only once of those two items should be expose
>- A valid signature scalar $s$
>- The secret nonce $r$ 
>


#### Secret Hint 

>[!info] We can directly link knowledge of the adaptor secret $y$ to knowledge of a private key

Bob can give Alice a hint toward his private key $k$, as a way of committing the adaptor secret $y$ to also reveal $k$

$z = y + k$

Alice can verify the hint, if she knows the public key of Bob 

$P = k \times G$

How Alice verifies:
- $z = y + x$
- $P = k \times G$
- $Y = y \times G$

$z \times G = (y + k) \times G$
= $y \times G$ + $k \times G$
= $Y + P$

>[!warning] $z$ must be share privately 



