# IDKPoC: PVAC-HFHE Division Vulnerability & Plaintext Recovery

## 1. The Vulnerability: Divisor Leakage

The `ct_div_const(A, k)` function is implemented as a simple scaling operation:

```cpp
// include/pvac/ops/arithmetic.hpp
inline Cipher ct_div_const(const PubKey& pk, const Cipher& A, const Fp& k) {
    return ct_scale(pk, A, fp_inv(k));
}
```

The `ct_scale` function clones the entire ciphertext structure and only multiplies the edge weights. Crucially, it **reuses the same layer seeds** as the original ciphertext.

### The Leak

Because the structure and seeds are identical, the random component **R** for each layer is the same in both the original `a.ct` and the result `divresult.ct`.

1. **Original weight**: w_i = r_i \* R
2. **Divided weight**: w'\_i = (r_i _ inv(k)) _ R

An attacker can compute the ratio:
**Ratio = w_i / w'\_i = (r_i _ R) / (r_i _ inv(k) \* R) = 1 / inv(k) = k**

By extracting the "G-sums" (which represent R \* v) from the public coefficients and exponents, the divisor **k** is leaked instantly.

---

## 2. Plaintext Recovery: Recovering a = 5

Once the divisor **k = 7** is recovered through the ratio attack, and given the result of the division (which is extractable from the ciphertext's G-sum without the secret key), we can recover the original dividend **a**.

In the field F_p (where p = 2^64 - 1), the division result is:
**result = a \* inv(k) (mod p)**

To recover **a**:
**a = result \* k (mod p)**

### Verification (Javascript)

Using the values from the test run:

- **Divisor (k):** 7
- **Division Result:** 5270498306774157605

The following logic recovers the original value:

```javascript
const p = 2n ** 64n - 1n;
const divisor = 7n;
const divResult = 5270498306774157605n;

const recovered = (divResult * divisor) % p;
console.log("Recovered dividend:", recovered.toString()); // Output: 5
```

### Source Files

- **[tests/create_division.cpp](tests/create_division.cpp)**: Generates the vulnerable ciphertexts.
- **[tests/exploit_division.cpp](tests/exploit_division.cpp)**: Performs the attack to recover the hidden divisor.
- **[tests/getdivideresult.js](tests/getdivideresult.js)**: Verifies the plaintext recovery logic in Javascript.

## Conclusion

The division operation in PVAC fails to provide privacy because:

1. **Divisor Data is Leaked**: The scaling factor **k** is exposed by seed reuse.
2. **Dividend is Recoverable**: Once K (divisor) is known, the original value **a** is trivially recovered from the quotient.
