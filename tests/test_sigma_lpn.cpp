#include <pvac/pvac.hpp>

#include <vector>
#include <random>
#include <cstdint>
#include <cassert>
#include <cmath>
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

static bool gauss_mod2_solve(const std::vector<BitVec>& rows,
                             const std::vector<uint8_t>& rhs,
                             std::vector<uint8_t>& sol, int m) {
    int n = (int)rows.size();
    if (n == 0 || m <= 0) return false;

    size_t wlen = (m + 63) / 64;
    std::vector<std::vector<uint64_t>> M(n, std::vector<uint64_t>(wlen));
    std::vector<uint8_t> b = rhs;

    for (int i = 0; i < n; ++i) {
        for (size_t w = 0; w < wlen; ++w) {
            M[i][w] = rows[i].w[w];
        }
    }

    std::vector<int> pivot_row(m, -1);
    int row = 0;

    for (int col = 0; col < m && row < n; ++col) {
        size_t w = (size_t)col / 64;
        uint64_t mask = 1ull << (col & 63);

        int sel = -1;
        for (int i = row; i < n; ++i) {
            if (M[i][w] & mask) { sel = i; break; }
        }
        if (sel == -1) continue;

        if (sel != row) {
            std::swap(M[sel], M[row]);
            std::swap(b[sel], b[row]);
        }

        pivot_row[col] = row;

        for (int i = 0; i < n; ++i) {
            if (i == row) continue;
            if (M[i][w] & mask) {
                for (size_t j = 0; j < wlen; ++j) {
                    M[i][j] ^= M[row][j];
                }
                b[i] ^= b[row];
            }
        }
        row++;
    }

    for (int i = 0; i < n; ++i) {
        bool zero = true;
        for (size_t j = 0; j < wlen; ++j) {
            if (M[i][j] != 0) { zero = false; break; }
        }
        if (zero && b[i]) return false;
    }

    sol.assign((size_t)m, 0);
    for (int col = m - 1; col >= 0; --col) {
        int r = pivot_row[col];
        if (r < 0) { sol[col] = 0; continue; }

        uint8_t val = b[r];
        for (int c = col + 1; c < m; ++c) {
            if (M[r][c / 64] & (1ull << (c & 63))) {
                val ^= sol[c];
            }
        }
        sol[col] = val;
    }
    return true;
}

int main() {
    std::cout << "- sigma lpn test -\n";

    Params prm;
    PubKey pk;
    SecKey sk;
    keygen(prm, pk, sk);

    int m = pk.prm.m_bits;
    const int S = 20;

    std::vector<BitVec> sigmas;
    sigmas.reserve((size_t)S);

    long double ones = 0;
    for (int i = 0; i < S; ++i) {
        Nonce128 nonce = make_nonce128();
        uint64_t ztag = prg_layer_ztag(pk.canon_tag, nonce);
        uint16_t idx = (uint16_t)(csprng_u64() % (uint64_t)pk.prm.B);
        uint8_t ch = (uint8_t)(csprng_u64() & 1ull);
        uint64_t salt = csprng_u64();

        BitVec s = sigma_from_H(pk, ztag, nonce, idx, ch, salt);
        ones += (long double)s.popcnt();
        sigmas.push_back(std::move(s));
    }

    long double N = (long double)S * (long double)m;
    long double exp = N * 0.5L;
    long double var = N * 0.5L * 0.5L;
    long double z = (ones - exp) / std::sqrt((double)var);
    std::cout << "sigma dens: z = " << (double)z << "\n";
    assert(fabsl(z) < 6.0L);

    const int P = 10;
    long double inter_sum = 0;
    std::mt19937_64 rng(0x5555aaaaf00df00dull);
    std::uniform_int_distribution<int> dist(0, S - 1);

    for (int t = 0; t < P; ++t) {
        int i = dist(rng);
        int j = dist(rng);
        if (i == j) { t--; continue; }

        const BitVec& a = sigmas[(size_t)i];
        const BitVec& b = sigmas[(size_t)j];

        size_t words = (a.nbits + 63) / 64;
        uint64_t w = 0;
        for (size_t k = 0; k < words; ++k) {
            w += (uint64_t)__builtin_popcountll(a.w[k] & b.w[k]);
        }
        inter_sum += (long double)w;
    }

    long double N2 = (long double)P * (long double)m;
    long double exp2 = N2 * 0.25L;
    long double var2 = N2 * 0.25L * 0.75L;
    long double z2 = (inter_sum - exp2) / std::sqrt((double)var2);

    std::cout << "sigma intersect: z = " << (double)z2 << "\n";
    assert(fabsl(z2) < 6.0L);

    std::cout << "sigma dist: ok\n";

    {
        std::mt19937_64 rng2(0x4242424242424242ull);

        int m_proj = std::min(512, m);
        int n_rows = 4 * m_proj;
        double tau = 0.125;

        std::vector<BitVec> rows;
        rows.reserve((size_t)n_rows);

        for (int i = 0; i < n_rows; ++i) {
            Nonce128 nonce = make_nonce128();
            uint64_t ztag = prg_layer_ztag(pk.canon_tag, nonce);
            uint16_t idx = (uint16_t)(csprng_u64() % (uint64_t)pk.prm.B);
            uint8_t ch = (uint8_t)(csprng_u64() & 1ull);
            uint64_t salt = csprng_u64();

            BitVec full = sigma_from_H(pk, ztag, nonce, idx, ch, salt);

            BitVec row = BitVec::make(m_proj);
            size_t wlen = (size_t)((m_proj + 63) / 64);
            for (size_t w = 0; w < wlen; ++w) {
                row.w[w] = full.w[w];
            }
            if (m_proj % 64) {
                row.w[wlen - 1] &= (1ull << (m_proj % 64)) - 1;
            }
            rows.push_back(std::move(row));
        }

        BitVec secret = BitVec::make(m_proj);
        size_t wlen_s = (size_t)((m_proj + 63) / 64);
        for (size_t w = 0; w < wlen_s; ++w) {
            secret.w[w] = rng2();
        }
        if (m_proj % 64) {
            secret.w[wlen_s - 1] &= (1ull << (m_proj % 64)) - 1;
        }

        std::bernoulli_distribution noise(tau);
        std::vector<uint8_t> y(n_rows);
        int wt = 0;
        for (int i = 0; i < n_rows; ++i) {
            uint8_t e = noise(rng2) ? 1 : 0;
            y[i] = bitvec_dot2(rows[i], secret) ^ e;
            wt += e;
        }

        double expected = tau * n_rows;
        double sigma_n = std::sqrt(n_rows * tau * (1.0 - tau));
        double z_noise = (wt - expected) / sigma_n;
        std::cout << "sigma to lpn noise: wt = " << wt
                  << " exp = " << expected
                  << " z = " << z_noise << "\n";
        assert(std::fabs(z_noise) < 6.0);

        // for unbelivers (anticipating) :D
        std::vector<uint8_t> sol;
        bool ok = gauss_mod2_solve(rows, y, sol, m_proj);
        assert(!ok);
        std::cout << "sigma to lpn: gauss fail as expected\n";
        //
    }

    std::cout << "PASS\n";
    return 0;
}
