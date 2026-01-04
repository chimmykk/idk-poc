#include <pvac/pvac.hpp>

#include <cstdint>
#include <cmath>
#include <cassert>
#include <iostream>

using namespace pvac;

using u128 = unsigned __int128;

static inline bool fp_eq(const Fp& a, const Fp& b) {
    return a.lo == b.lo && a.hi == b.hi;
}

static inline Fp fp_one() {
    return fp_from_u64(1);
}

static inline Fp fp_zero() {
    return fp_from_u64(0);
}

static Fp fp_rand_any() {
    uint64_t r = csprng_u64();
    if (r & 1ull) return fp_zero();
    return rand_fp_nonzero();
}

static Fp fp_pow_big(Fp a, u128 e) {
    Fp r = fp_one();
    while (e) {
        if (e & 1) r = fp_mul(r, a);
        a = fp_mul(a, a);
        e >>= 1;
    }
    return r;
}

int main() {
    std::cout << "- fp core test -\n";

    const int N1 = 20000;
    const int N2 = 20000;
    const int N3 = 20000;

    for (int i = 0; i < N1; ++i) {
        Fp a = fp_rand_any();
        Fp b = fp_rand_any();
        Fp c = fp_sub(fp_add(a, b), b);
        assert(fp_eq(c, a));
    }
    std::cout << "add/sub: ok\n";

    for (int i = 0; i < N2; ++i) {
        Fp a = fp_rand_any();
        Fp b = fp_rand_any();
        Fp c = fp_rand_any();
        Fp l = fp_mul(fp_mul(a, b), c);
        Fp r = fp_mul(a, fp_mul(b, c));
        assert(fp_eq(l, r));
    }
    std::cout << "mul assoc: ok\n";

    for (int i = 0; i < N3; ++i) {
        Fp a = rand_fp_nonzero();
        Fp inv = fp_inv(a);
        Fp prod = fp_mul(a, inv);
        assert(fp_eq(prod, fp_one()));
    }
    std::cout << "inv: ok\n";

    const u128 P = (((u128)1) << 127) - 1;
    const int N4 = 2000;

    for (int i = 0; i < N4; ++i) {
        Fp a = fp_rand_any();
        Fp ap = fp_pow_big(a, P);
        assert(fp_eq(ap, a));

        if (!fp_eq(a, fp_zero())) {
            Fp ap1 = fp_pow_big(a, P - 1);
            assert(fp_eq(ap1, fp_one()));

            Fp inv2 = fp_pow_big(a, P - 2);
            Fp prod2 = fp_mul(a, inv2);
            assert(fp_eq(prod2, fp_one()));
        }
    }
    std::cout << "fermat: ok\n";

    std::cout << "PASS\n";
    return 0;
}