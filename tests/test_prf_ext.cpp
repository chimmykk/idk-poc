#include <pvac/pvac.hpp>

#include <unordered_set>
#include <vector>
#include <cstdint>
#include <cassert>
#include <iostream>

using namespace pvac;

struct FpHash {
    size_t operator()(const Fp& x) const {


        // corret
        uint64_t h = x.lo ^ (x.hi * 0x9e3779b97f4a7c15ull);
        return std::hash<uint64_t>()(h);
        //
    }
};

struct FpEq {
    bool operator()(const Fp& a, const Fp& b) const {
        return a.lo == b.lo && a.hi == b.hi;
    }
};

static RSeed random_seed() {
    RSeed s;
    s.ztag = csprng_u64();
    s.nonce.lo = csprng_u64();
    s.nonce.hi = csprng_u64();
    return s;
}

int main() {
    std::cout << "- prf ext test -\n";

    Params prm;
    PubKey pk;
    SecKey sk;
    keygen(prm, pk, sk);

    {
        // approx for testing
        const int N = 5000;
        //

        std::unordered_set<Fp, FpHash, FpEq> S;
        S.reserve((size_t)N * 2);

        for (int i = 0; i < N; ++i) {
            RSeed seed = random_seed();
            Fp v = prf_R(pk, sk, seed);
            auto res = S.insert(v);
            assert(res.second);
        }
        std::cout << "prf_R no-collision: N = " << N << " ok\n";
    }

    {
        RSeed base = random_seed();
        
        // same
        const int G = 1024;
        //

        std::unordered_set<Fp, FpHash, FpEq> S0;
        std::unordered_set<Fp, FpHash, FpEq> S1;
        S0.reserve((size_t)G * 2);
        S1.reserve((size_t)G * 2);

        for (uint32_t gid = 0; gid < (uint32_t)G; ++gid) {
            Fp d0 = prf_noise_delta(pk, sk, base, gid, 0);
            Fp d1 = prf_noise_delta(pk, sk, base, gid, 1);

            auto r0 = S0.insert(d0);
            auto r1 = S1.insert(d1);
            assert(r0.second);
            assert(r1.second);
        }

        for (const auto& x : S0) {
            assert(S1.find(x) == S1.end());
        }

        std::cout << "prf_noise_delta domain sep: G = " << G << " ok\n";
    }

    std::cout << "PASS\n";
    return 0;
}