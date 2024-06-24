# Adaptor signature
Source: https://bitcoinops.org/en/topics/adaptor-signatures/

## Coin swap in mathematical terms
1. Scalar: 
* something that has size but no direction, such as a quantity, distance, speed, or temperature
* (physics) velocity is a vector quantity, while speed is the corresponding scalar quantity, because it does not have a direction.

2. Point: 
* In affine coordinates, a point `P` on the curve is represented as `(X, Y)`.
* Jacobian projective coordinates are more expressive since it introduces a new variable `Z`. Thus, a point `P` on the elliptic curve is represented as `(X, Y, Z)`.
* The primary benefit of using Jacobian projective coordinates is the **reduction in the number of field inversions** required during point addition and point doubling operations. Field inversions are computationally expensive compared to multiplications.

## There is a problem around R value
with the same s, e, and P, R is derived diffently? but why?