#include <pvac/pvac.hpp>

#include <vector>
#include <random>
#include <cstdint>
#include <cassert>
#include <iostream>

using namespace pvac;

static uint8_t bitvec_dot2(const BitVec& a, const BitVec& b) {
    size_t words = (a.nbits + 63) / 64;
    uint64_t parity = 0;
    for (size_t i = 0; i < words; ++i) {
        parity ^= (uint64_t)__builtin_popcountll(a.w[i] & b.w[i]);
    }
    return (uint8_t)(parity & 1ull);
}

static std::vector<uint8_t> random_bits(int m, std::mt19937_64& rng) {
    std::vector<uint8_t> v((size_t)m);
    for (int i = 0; i < m; ++i) v[(size_t)i] = (uint8_t)(rng() & 1ull);
    return v;
}

static BitVec bitvec_from_bits(const std::vector<uint8_t>& bits) {
    int m = (int)bits.size();
    BitVec v = BitVec::make(m);
    size_t words = (m + 63) / 64;
    for (size_t i = 0; i < words; ++i) v.w[i] = 0;
    for (int i = 0; i < m; ++i) {
        if (bits[(size_t)i]) {
            v.w[(size_t)i / 64] |= (1ull << (i & 63));
        }
    }
    if (m % 64) {
        v.w[words - 1] &= (1ull << (m % 64)) - 1;
    }
    return v;
}

static uint64_t popcnt_bits(const std::vector<uint8_t>& bits) {
    uint64_t c = 0;
    for (uint8_t b : bits) c += (b & 1u);
    return c;
}

static uint8_t dot_bits(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    uint64_t s = 0;
    size_t n = a.size();
    for (size_t i = 0; i < n; ++i) s += (uint64_t)((a[i] & 1u) & (b[i] & 1u));
    return (uint8_t)(s & 1ull);
}

int main() {
    std::cout << "- bitvec test -\n";

    std::mt19937_64 rng(0xabcdef1234567890ull);

    const int N = 5000;
    const int m_small = 127;
    const int m_large = 4096;

    for (int t = 0; t < N; ++t) {
        int m = (t & 1) ? m_small : m_large;

        auto a_bits = random_bits(m, rng);
        auto b_bits = random_bits(m, rng);

        BitVec a = bitvec_from_bits(a_bits);
        BitVec b = bitvec_from_bits(b_bits);

        uint64_t pa = a.popcnt();
        uint64_t pb = b.popcnt();
        assert(pa == popcnt_bits(a_bits));
        assert(pb == popcnt_bits(b_bits));

        BitVec x = a;
        x.xor_with(b);
        std::vector<uint8_t> xor_bits((size_t)m);
        for (int i = 0; i < m; ++i) xor_bits[(size_t)i] = (uint8_t)((a_bits[(size_t)i] ^ b_bits[(size_t)i]) & 1u);

        size_t words = (m + 63) / 64;
        for (int i = 0; i < m; ++i) {
            uint64_t w = x.w[(size_t)i / 64];
            uint8_t bit = (uint8_t)((w >> (i & 63)) & 1ull);
            assert(bit == xor_bits[(size_t)i]);
        }
        if (m % 64) {
            uint64_t tail = x.w[words - 1] >> (m % 64);
            assert(tail == 0);
        }

        BitVec self = a;
        self.xor_with(a);
        assert(self.popcnt() == 0);

        uint8_t d1 = bitvec_dot2(a, b);
        uint8_t d2 = dot_bits(a_bits, b_bits);
        assert(d1 == d2);
    }
    std::cout << "popcnt/xor/dot: ok\n";

    std::cout << "PASS\n";
    return 0;
}