#include <pvac/pvac.hpp>

#include <vector>
#include <random>
#include <cstdint>
#include <cassert>
#include <iostream>

using namespace pvac;

static bool fp_eq(const Fp& a, const Fp& b) {
    return (a.lo == b.lo) && (a.hi == b.hi);
}

int main() {
    std::cout << "- ct fuzz test -\n";

    Params prm;
    PubKey pk;
    SecKey sk;
    keygen(prm, pk, sk);

    std::mt19937_64 rng(0x123456789abcdef0ull);

    const int K = 4;
    uint64_t vals[K];
    for (int i = 0; i < K; ++i) {
        vals[i] = (uint64_t)(rng() & 0xFFFFull);
    }

    Cipher enc[K];
    for (int i = 0; i < K; ++i) {
        enc[i] = enc_value(pk, sk, vals[i]);
        Fp dec = dec_value(pk, sk, enc[i]);
        assert(fp_eq(dec, fp_from_u64(vals[i])));
    }

    Cipher cz = enc_zero_depth(pk, sk, 0);
    Fp dz = dec_value(pk, sk, cz);
    assert(fp_eq(dz, fp_from_u64(0)));

    Cipher a_plus_zero = ct_add(pk, enc[0], cz);
    Fp d0 = dec_value(pk, sk, a_plus_zero);
    assert(fp_eq(d0, fp_from_u64(vals[0])));

    const int N_TRIALS = 4;
    const int MIN_STEPS = 3;
    const int MAX_STEPS = 6;

    for (int t = 0; t < N_TRIALS; ++t) {
        int idx0 = (int)(rng() % K);
        Fp acc_plain = fp_from_u64(vals[idx0]);
        Cipher acc_ct = enc[idx0];

        int mul_used = 0;
        int steps = MIN_STEPS + (int)(rng() % (MAX_STEPS - MIN_STEPS + 1));

        for (int s = 0; s < steps; ++s) {
            int idx = (int)(rng() % K);
            Fp rhs_plain = fp_from_u64(vals[idx]);
            Cipher rhs_ct = enc[idx];

            int op = (int)(rng() % 3);
            if (op == 2 && mul_used >= 2) {
                op = (int)(rng() % 2);
            }

            if (op == 0) {
                acc_plain = fp_add(acc_plain, rhs_plain);
                acc_ct = ct_add(pk, acc_ct, rhs_ct);
            } else if (op == 1) {
                acc_plain = fp_sub(acc_plain, rhs_plain);
                acc_ct = ct_sub(pk, acc_ct, rhs_ct);
            } else {
                acc_plain = fp_mul(acc_plain, rhs_plain);
                acc_ct = ct_mul(pk, acc_ct, rhs_ct);
                ++mul_used;
            }
        }

        Fp got = dec_value(pk, sk, acc_ct);
        if (!fp_eq(got, acc_plain)) {
            std::cerr << "mismatch in trial " << t << "\n";
            std::cerr << "expected lo = " << acc_plain.lo << " hi = " << acc_plain.hi << "\n";
            std::cerr << "got lo = " << got.lo       << " hi = " << got.hi       << "\n";
            assert(false);
        }
    }

    std::cout << "ct-fuzz: ok\n";
    std::cout << "PASS\n";
    return 0;
}