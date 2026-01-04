#include <pvac/core/ct_safe.hpp>
#include <pvac/core/field.hpp>
#include <pvac/core/bitvec.hpp>

#include <iostream>
#include <random>
#include <array>
#include <cstring>
#include <cstdlib>

using namespace pvac;
using namespace pvac::ct;

static void must(bool ok, const char* name) {
    if (!ok) {
        std::cerr << "[ct] FAIL: " << name << std::endl;
        std::exit(1);
    }
}

static void test_u64_basic() {
    must(is_zero(u64{0}) == u64{1}, "u64 is_zero(0)");
    must(is_zero(u64{1}) == u64{0}, "u64 is_zero(1)");
    must(is_nonzero(u64{0}) == u64{0}, "u64 is_nonzero(0)");
    must(is_nonzero(u64{1}) == u64{1}, "u64 is_nonzero(1)");

    u64 m0 = mask_from_bit(u64{0});
    u64 m1 = mask_from_bit(u64{1});
    must(m0 == u64{0}, "u64 mask_from_bit(0)");
    must(m1 == ~u64{0}, "u64 mask_from_bit(1)");

    u64 a = 0xAAAAAAAAAAAAAAAAull;
    u64 b = 0x5555555555555555ull;
    must(select(m1, a, b) == a, "u64 select m1");
    must(select(m0, a, b) == b, "u64 select m0");

    u64 x = a;
    u64 y = b;
    cswap(m1, x, y);
    must(x == b && y == a, "u64 cswap on");
    cswap(m0, x, y);
    must(x == b && y == a, "u64 cswap off");

    must(min(u64{1}, u64{2}) == u64{1}, "u64 min");
    must(max(u64{1}, u64{2}) == u64{2}, "u64 max");
    must(abs_diff(u64{7}, u64{3}) == u64{4}, "u64 abs_diff1");
    must(abs_diff(u64{3}, u64{7}) == u64{4}, "u64 abs_diff2");
}

static void test_u64_random() {
    std::mt19937_64 rng(12345);
    for (int i = 0; i < 1000; ++i) {
        u64 a = rng();
        u64 b = rng();

        must((eq(a, b) != 0) == (a == b), "u64 eq rnd");
        must((neq(a, b) != 0) == (a != b), "u64 neq rnd");
        must((lt(a, b) != 0) == (a <  b), "u64 lt rnd");
        must((gt(a, b) != 0) == (a >  b), "u64 gt rnd");
        must((le(a, b) != 0) == (a <= b), "u64 le rnd");
        must((ge(a, b) != 0) == (a >= b), "u64 ge rnd");

        u64 s = saturating_add(a, b);
        unsigned __int128 sum = (unsigned __int128)a + (unsigned __int128)b;
        u64 exp_s = (sum > (unsigned __int128)std::numeric_limits<u64>::max())
                    ? std::numeric_limits<u64>::max()
                    : (u64)sum;
        must(s == exp_s, "u64 sat_add rnd");

        u64 d = saturating_sub(a, b);
        u64 exp_d = (a >= b) ? (a - b) : 0;
        must(d == exp_d, "u64 sat_sub rnd");
    }
}

static void test_fp_basic() {
    Fp z = fp_from_u64(0);
    Fp o = fp_from_u64(1);
    Fp two = fp_from_u64(2);

    must(fp_is_zero(z) == u64{1}, "fp zero");
    must(fp_is_zero(o) == u64{0}, "fp nonzero");
    must(fp_eq(z, z) == u64{1}, "fp eq self");
    must(fp_eq(z, o) == u64{0}, "fp neq basic");
    must(fp_is_one(o) == u64{1}, "fp is_one");
    must(fp_is_one(two) == u64{0}, "fp not one");

    Fp s = fp_add(o, two);
    Fp t = fp_add(two, o);
    must(fp_eq(s, t) == u64{1}, "fp add commut");

    Fp d = fp_sub(s, two);
    must(fp_eq(d, o) == u64{1}, "fp sub inverse");
}

static void test_fp_random() {
    std::mt19937_64 rng(54321);
    for (int i = 0; i < 200; ++i) {
        u64 ax = rng();
        u64 bx = rng();
        Fp a = fp_from_u64(ax);
        Fp b = fp_from_u64(bx);

        must((fp_eq(a, b) != 0) == (ax == bx), "fp eq rnd");

        Fp s = fp_add(a, b);
        Fp diff = fp_sub(s, b);
        must(fp_eq(diff, a) != 0, "fp add/sub rnd");

        if (ax == 0) {
            continue;
        }
        Fp inv = fp_inv(a);
        Fp prod = fp_mul(a, inv);
        Fp one = fp_from_u64(1);
        must(fp_eq(prod, one) != 0, "fp inv rnd");
    }
}

static void test_fp_cswap() {
    Fp a = fp_from_u64(10);
    Fp b = fp_from_u64(20);
    u64 m1 = mask_from_bit(u64{1});
    u64 m0 = mask_from_bit(u64{0});

    fp_cswap(m1, a, b);
    must(fp_eq(a, fp_from_u64(20)) != 0, "fp cswap on a");
    must(fp_eq(b, fp_from_u64(10)) != 0, "fp cswap on b");

    fp_cswap(m0, a, b);
    must(fp_eq(a, fp_from_u64(20)) != 0, "fp cswap off a");
    must(fp_eq(b, fp_from_u64(10)) != 0, "fp cswap off b");
}

static void test_bitvec() {
    BitVec a = BitVec::make(128);
    BitVec b = BitVec::make(128);

    a.w[0] = 0xAAAAAAAAAAAAAAAAull;
    b.w[0] = 0x5555555555555555ull;

    u64 m1 = mask_from_bit(u64{1});
    u64 m0 = mask_from_bit(u64{0});

    BitVec c = bv_select(m1, a, b);
    must(c.w[0] == a.w[0], "bv_select m1");
    c = bv_select(m0, a, b);
    must(c.w[0] == b.w[0], "bv_select m0");

    BitVec x = a;
    BitVec y = b;

    bv_cswap(m1, x, y);
    must(x.w[0] == b.w[0] && y.w[0] == a.w[0], "bv_cswap on");
    bv_cswap(m0, x, y);
    must(x.w[0] == b.w[0] && y.w[0] == a.w[0], "bv_cswap off");
}

static void test_lookup_store() {
    std::array<u64, 8> arr{};
    for (std::size_t i = 0; i < arr.size(); ++i) {
        arr[i] = (u64)(i * 3 + 7);
    }

    for (std::size_t i = 0; i < arr.size(); ++i) {
        u64 v = lookup(arr, i);
        must(v == arr[i], "lookup array");
    }

    std::array<u64, 8> arr2{};
    for (std::size_t i = 0; i < arr2.size(); ++i) {
        arr2[i] = 0;
    }
    for (std::size_t i = 0; i < arr2.size(); ++i) {
        store(arr2, i, (u64)(i + 100));
    }
    for (std::size_t i = 0; i < arr2.size(); ++i) {
        must(arr2[i] == (u64)(i + 100), "store array");
    }

    u64 raw[4] = {1, 2, 3, 4};
    for (std::size_t i = 0; i < 4; ++i) {
        u64 v = lookup(raw, i);
        must(v == raw[i], "lookup raw");
    }
    for (std::size_t i = 0; i < 4; ++i) {
        store(raw, i, (u64)(10 + i));
    }
    for (std::size_t i = 0; i < 4; ++i) {
        must(raw[i] == (u64)(10 + i), "store raw");
    }
}

static void test_memory() {
    std::uint8_t a[32];
    std::uint8_t b[32];
    std::uint8_t c[32];

    for (int i = 0; i < 32; ++i) {
        a[i] = (std::uint8_t)i;
        b[i] = (std::uint8_t)i;
        c[i] = 0;
    }

    must(memeq(a, b, 32) == u64{1}, "memeq equal");
    b[5] ^= 1u;
    must(memeq(a, b, 32) == u64{0}, "memeq diff");
    b[5] ^= 1u;

    std::memset(c, 0, 32);
    memcpy_if(u64{0}, c, a, 32);
    must(memeq(c, a, 32) == u64{0}, "memcpy_if off");
    memcpy_if(u64{1}, c, a, 32);
    must(memeq(c, a, 32) == u64{1}, "memcpy_if on");

    memset_if(u64{0}, c, 0xFFu, 32);
    must(memeq(c, a, 32) == u64{1}, "memset_if off");
    memset_if(u64{1}, c, 0u, 32);
    must(memeq(c, a, 32) == u64{0}, "memset_if on");
    for (int i = 0; i < 32; ++i) {
        must(c[i] == 0u, "memset_if value");
    }

    for (int i = 0; i < 32; ++i) {
        c[i] = (std::uint8_t)(i + 5);
    }
    memzero_if(u64{0}, c, 32);
    for (int i = 0; i < 32; ++i) {
        must(c[i] == (std::uint8_t)(i + 5), "memzero_if off");
    }
    memzero_if(u64{1}, c, 32);
    for (int i = 0; i < 32; ++i) {
        must(c[i] == 0u, "memzero_if on");
    }
}

int main() {
    std::cout << "- ct layer tests -" << std::endl;

    test_u64_basic();
    test_u64_random();
    test_fp_basic();
    test_fp_random();
    test_fp_cswap();
    test_bitvec();
    test_lookup_store();
    test_memory();

    std::cout << "ct: all tests passed" << std::endl;
    return 0;
}
