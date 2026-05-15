# ECDSA

ECDSA a signature algorithm based on [elliptic curve](elliptic-curve.md) cryptography. 


## Elements 

- A random known curve point $G$

For example for bitcoin:
```tex
G =(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)
```

- private key: $k$ , which is a big random number 
- Public key $P$
	- $P$ = $k$ x $G$


> The `x` operation here is point multiplication in elliptic curve, which is different from the scalar multiplication we learned in linear algebra. 

## Signing 
### Prerequisites 

- Private key: $k$
- Public key: $P = k \times G$
- Messgage: $m$ (integer)

### Algorithm 
1. choose a random number $z$ (a nonce)
2. calculate: $R = z \times G$ (a point $R$ on a curve)
3. X-coordinate of $R$: $r$ (take only x coordinate of $R$) 
4. Calculate: $s = \frac{m + r \times k}{z}$   ($m$ is the msg to sign)
5. Signature:  ($r, s$)

The formula at the bottom 
`SIG_ECDSA = (private key, message) = (r, s)`


## Verify 

### Prerequisites 
 - Obtain the public key $P$
 - Obtain the signature: ($r, s$)
 - Obtain the message: $m$

### Algorithm 

1. $u = \frac{m}{s}$
2. $v= \frac{r}{s}$
4.  $N = u \times G + v \times P$
5. Assert if `X-coordinate of N` == $R$


## Assertion process 

The information we get publicly is: $u$, $v$, $R$, $P$

The assertion formula is:
$u \times G + v \times P = R$ 

We have: 
$u \times G + v \times P = \frac{m}{s} \times G + \frac{r}{s} \times P = \frac{m}{s} \times G + \frac{r}{s} \times (k \times G) = \frac{m+rk}{s} \times G = z \times G = R$