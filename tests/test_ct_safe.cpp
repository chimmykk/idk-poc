#include <pvac/pvac.hpp>

#include <vector>
#include <random>
#include <cstdint>
#include <cassert>
#include <chrono>
#include <iostream>
#include <algorithm>
using namespace pvac;
using Clock = std::chrono::steady_clock;
static uint64_t dur_us(Clock::time_point a, Clock::time_point b) {
    return (uint64_t)std::chrono::duration_cast<std::chrono::microseconds>(b - a).count();
}

static uint64_t bench_fp_add(const std::vector<Fp>& xs,
                             const std::vector<Fp>& ys,
                             int rounds) {
    Fp acc = fp_from_u64(0);
    auto t0 = Clock::now();
    for (int r = 0; r < rounds; ++r) {
        for (size_t i = 0; i < xs.size(); ++i) {
            Fp tmp = fp_add(xs[i], ys[i]);
            acc = fp_add(acc, tmp);
        }
    }
    auto t1 = Clock::now();
    volatile uint64_t sink = acc.lo ^ acc.hi;
    (void)sink;
    return dur_us(t0, t1);
}

static uint64_t bench_fp_mul(const std::vector<Fp>& xs,
                             const std::vector<Fp>& ys,
                             int rounds) {
    Fp acc = fp_from_u64(1);
    auto t0 = Clock::now();
    for (int r = 0; r < rounds; ++r) {
        for (size_t i = 0; i < xs.size(); ++i) {
            Fp tmp = fp_add(xs[i], ys[i]);
            acc = fp_mul(acc, tmp);
        }
    }
    auto t1 = Clock::now();
    volatile uint64_t sink = acc.lo ^ acc.hi;
    (void)sink;
    return dur_us(t0, t1);
}

static uint64_t bench_fp_inv(const std::vector<Fp>& xs,
                             int rounds) {
    Fp acc = fp_from_u64(1);
    auto t0 = Clock::now();
    for (int r = 0; r < rounds; ++r) {
        for (size_t i = 0; i < xs.size(); ++i) {
            Fp inv = fp_inv(xs[i]);
            acc = fp_mul(acc, inv);
        }
    }
    auto t1 = Clock::now();
    volatile uint64_t sink = acc.lo ^ acc.hi;
    (void)sink;
    return dur_us(t0, t1);
}

static uint64_t bench_sigma(const PubKey& pk,
                            const RSeed& seed,
                            bool random_indices,
                            std::mt19937_64& rng,
                            int n,
                            int rounds) {
    uint64_t acc = 0;
    auto t0 = Clock::now();
    for (int r = 0; r < rounds; ++r) {
        for (int i = 0; i < n; ++i) {
            uint16_t idx;
            uint8_t ch;
            if (random_indices) {
                idx = (uint16_t)(rng() % (uint64_t)pk.prm.B);
                ch = (uint8_t)(rng() & 1ull);
            } else {
                idx = 0;
                ch = 0;
            }
            uint64_t salt = rng();
            BitVec s = sigma_from_H(pk, seed.ztag, seed.nonce, idx, ch, salt);
            acc ^= (uint64_t)s.popcnt();
        }
    }
    auto t1 = Clock::now();
    volatile uint64_t sink = acc;
    (void)sink;
    return dur_us(t0, t1);
}

static double ratio(uint64_t a, uint64_t b) {
    uint64_t hi = std::max(a, b);
    uint64_t lo = std::min(a, b);
    if (lo == 0) return 1.0;
    return (double)hi / (double)lo;
}

int main() {
    std::cout << "- ct safe test -\n";

    std::mt19937_64 rng(0x123456789abcdef0ull);

    Params prm;
    PubKey pk;
    SecKey sk;
    keygen(prm, pk, sk);

    const int N = 512;
    const int R = 64;

    std::vector<Fp> xs_rand(N), ys_rand(N), xs_hot(N), ys_hot(N);

    for (int i = 0; i < N; ++i) {
        uint64_t rx = rng();
        uint64_t ry = rng();
        xs_rand[i] = fp_from_u64(rx);
        ys_rand[i] = fp_from_u64(ry);
    }

    Fp hot_x = fp_from_u64(1);
    Fp hot_y = fp_from_u64(2);
    for (int i = 0; i < N; ++i) {
        xs_hot[i] = hot_x;
        ys_hot[i] = hot_y;
    }

    uint64_t t_add_rand = bench_fp_add(xs_rand, ys_rand, R);
    uint64_t t_add_hot  = bench_fp_add(xs_hot, ys_hot, R);
    double r_add = ratio(t_add_rand, t_add_hot);
    std::cout << "fp_add: hot = " << t_add_hot << " us rand = " << t_add_rand << " us ratio = " << r_add << "\n";
    assert(r_add < 3.0);

    uint64_t t_mul_rand = bench_fp_mul(xs_rand, ys_rand, R);
    uint64_t t_mul_hot  = bench_fp_mul(xs_hot, ys_hot, R);
    double r_mul = ratio(t_mul_rand, t_mul_hot);
    std::cout << "fp_mul: hot = " << t_mul_hot << " us rand = " << t_mul_rand << " us ratio = " << r_mul << "\n";
    assert(r_mul < 3.0);

    std::vector<Fp> inv_rand(N), inv_hot(N);
    for (int i = 0; i < N; ++i) {
        uint64_t rx = rng() | 1ull;
        inv_rand[i] = fp_from_u64(rx);
    }
    Fp hot_inv = fp_from_u64(3);
    for (int i = 0; i < N; ++i) {
        inv_hot[i] = hot_inv;
    }

    uint64_t t_inv_rand = bench_fp_inv(inv_rand, R / 2);
    uint64_t t_inv_hot  = bench_fp_inv(inv_hot, R / 2);
    double r_inv = ratio(t_inv_rand, t_inv_hot);
    std::cout << "fp_inv: hot = " << t_inv_hot << " us rand = " << t_inv_rand << " us ratio = " << r_inv << "\n";
    assert(r_inv < 3.0);

    const int N_sigma = 128;
    const int R_sigma = 16;

    RSeed seed;
    seed.nonce = make_nonce128();
    seed.ztag = prg_layer_ztag(pk.canon_tag, seed.nonce);

    uint64_t t_sig_fixed = bench_sigma(pk, seed, false, rng, N_sigma, R_sigma);
    uint64_t t_sig_rand  = bench_sigma(pk, seed, true,  rng, N_sigma, R_sigma);
    double r_sig = ratio(t_sig_fixed, t_sig_rand);
    std::cout << "sigma: fixed = " << t_sig_fixed << " us rand = " << t_sig_rand << " us ratio = " << r_sig << "\n";
    assert(r_sig < 3.0);

    std::cout << "ct-safe: ok\n";
    std::cout << "PASS\n";
    return 0;
}