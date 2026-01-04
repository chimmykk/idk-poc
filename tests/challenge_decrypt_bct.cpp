#include <pvac/pvac.hpp>
#include <iostream>
#include <fstream>
#include <cstring>

using namespace pvac;

// IO helpers
namespace io {
    auto get32 = [](std::istream& i) -> uint32_t {
        uint32_t x = 0; i.read(reinterpret_cast<char*>(&x), 4); return x;
    };
    auto get64 = [](std::istream& i) -> uint64_t {
        uint64_t x = 0; i.read(reinterpret_cast<char*>(&x), 8); return x;
    };
    auto getBv = [](std::istream& i) -> BitVec {
        auto b = BitVec::make((int)get32(i));
        for (size_t j = 0; j < (b.nbits + 63) / 64; ++j) b.w[j] = get64(i);
        return b;
    };
    auto getFp = [](std::istream& i) -> Fp {
        return {get64(i), get64(i)};
    };
}

namespace ser {
    using namespace io;
    auto getLayer = [](std::istream& i) -> Layer {
        Layer L{};
        L.rule = (RRule)i.get();
        if (L.rule == RRule::BASE) {
            L.seed.ztag = get64(i);
            L.seed.nonce.lo = get64(i);
            L.seed.nonce.hi = get64(i);
        } else if (L.rule == RRule::PROD) {
            L.pa = get32(i);
            L.pb = get32(i);
        } else {
            (void)get64(i); (void)get64(i); (void)get64(i);
        }
        return L;
    };
    auto getEdge = [](std::istream& i) -> Edge {
        Edge e{};
        e.layer_id = get32(i);
        i.read(reinterpret_cast<char*>(&e.idx), 2);
        e.ch = (uint8_t)i.get();
        i.get();
        e.w = getFp(i);
        e.s = getBv(i);
        return e;
    };
    auto getCipher = [](std::istream& i) -> Cipher {
        Cipher C;
        auto nL = get32(i), nE = get32(i);
        C.L.resize(nL); C.E.resize(nE);
        for (auto& L : C.L) L = getLayer(i);
        for (auto& e : C.E) e = getEdge(i);
        return C;
    };
}

namespace Magic {
    constexpr uint32_t CT = 0x66699666;
    constexpr uint32_t PK = 0x06660666;
    constexpr uint32_t VER = 1;
}

auto loadCts = [](const std::string& path) -> std::vector<Cipher> {
    std::ifstream i(path, std::ios::binary);
    if (!i || io::get32(i) != Magic::CT || io::get32(i) != Magic::VER)
        throw std::runtime_error("bad CT: " + path);
    std::vector<Cipher> cts(io::get64(i));
    for (auto& c : cts) c = ser::getCipher(i);
    return cts;
};

auto loadPk = [](const std::string& path) -> PubKey {
    std::ifstream i(path, std::ios::binary);
    if (!i || io::get32(i) != Magic::PK || io::get32(i) != Magic::VER)
        throw std::runtime_error("bad PK: " + path);
    PubKey pk;
    pk.prm.m_bits = io::get32(i);
    pk.prm.B = io::get32(i);
    pk.prm.lpn_t = io::get32(i);
    pk.prm.lpn_n = io::get32(i);
    pk.prm.lpn_tau_num = io::get32(i);
    pk.prm.lpn_tau_den = io::get32(i);
    pk.prm.noise_entropy_bits = io::get32(i);
    pk.prm.depth_slope_bits = io::get32(i);
    uint64_t t2 = io::get64(i);
    std::memcpy(&pk.prm.tuple2_fraction, &t2, 8);
    pk.prm.edge_budget = io::get32(i);
    pk.canon_tag = io::get64(i);
    i.read(reinterpret_cast<char*>(pk.H_digest.data()), 32);
    pk.H.resize(io::get64(i));
    for (auto& h : pk.H) h = io::getBv(i);
    pk.ubk.perm.resize(io::get64(i));
    for (auto& v : pk.ubk.perm) v = io::get32(i);
    pk.ubk.inv.resize(io::get64(i));
    for (auto& v : pk.ubk.inv) v = io::get32(i);
    pk.omega_B = io::getFp(i);
    pk.powg_B.resize(io::get64(i));
    for (auto& f : pk.powg_B) f = io::getFp(i);
    return pk;
};

Fp total_gsum(const PubKey& pk, const Cipher& C) {
    Fp acc = fp_from_u64(0);
    for (const auto& e : C.E) {
        Fp term = fp_mul(e.w, pk.powg_B[e.idx]);
        if (e.ch == SGN_P) acc = fp_add(acc, term);
        else acc = fp_sub(acc, term);
    }
    return acc;
}

int main() {
    std::cout << "==============================================\n";
    std::cout << "CHALLENGE: Decrypt b.ct Using ONLY pk.bin\n";
    std::cout << "==============================================\n\n";

    try {
        std::cout << "Loading ONLY public key (NO secret key!)...\n";
        PubKey pk = loadPk("bounty3_data/pk.bin");
        Cipher ct_b = loadCts("bounty3_data/b.ct")[0];
        std::cout << "✓ Loaded pk.bin and b.ct\n\n";

        std::cout << "=== ATTEMPT 1: Direct G-sum ===\n";
        Fp gsum = total_gsum(pk, ct_b);
        std::cout << "G-sum(b.ct) = 0x" << std::hex << gsum.hi << gsum.lo << std::dec << "\n";
        std::cout << "Decimal: " << gsum.lo << "\n";
        std::cout << "❌ This is NOT the plaintext!\n";
        std::cout << "   (Actual plaintext is 7, this is garbage)\n\n";

        std::cout << "Why? G-sum = R₀×(v+mask) + R₁×(-mask)\n";
        std::cout << "We don't know R₀ or R₁ (need secret key!)\n\n";

        std::cout << "=== ATTEMPT 2: Try all small values ===\n";
        std::cout << "Maybe we can guess by trying v = 1, 2, 3, ...\n\n";

        bool found = false;
        for (uint64_t guess = 1; guess <= 100; guess++) {
            // Can we verify if guess is correct?
            // NO! We would need to know R to check:
            // G-sum should equal R₀×(guess+mask) + R₁×(-mask)
            // But we don't know R or mask without secret key

            // Let's try anyway...
            Fp guess_fp = fp_from_u64(guess);

            // Check if gsum / guess gives us something reasonable?
            // This makes no sense without R...

            if (guess == 7) {
                std::cout << "Testing guess = 7...\n";
                std::cout << "❌ Cannot verify without secret key!\n";
                std::cout << "   We don't know what G-sum SHOULD be for v=7\n\n";
            }
        }

        std::cout << "=== ATTEMPT 3: Ratio Attack (like divisor exploit) ===\n";
        std::cout << "Can we use the divisor trick on b.ct?\n\n";

        std::cout << "NO! The divisor trick needs TWO related ciphertexts:\n";
        std::cout << "  - ct_a and ct_div that share the same seeds/R\n";
        std::cout << "  - b.ct is INDEPENDENT - fresh R values\n";
        std::cout << "  - No ratio to compute!\n\n";

        std::cout << "=== ATTEMPT 4: Brute force the PRF ===\n";
        std::cout << "To get R values, we need to evaluate:\n";
        std::cout << "  R = prf_R(pk, sk, seed)\n\n";
        std::cout << "But prf_R uses:\n";
        std::cout << "  - sk.prf_k (4 × 64-bit secret key)\n";
        std::cout << "  - sk.lpn_s_bits (LPN secret)\n\n";
        std::cout << "Security: ~2^128 for PRF key\n";
        std::cout << "          ~2^200 for LPN\n";
        std::cout << "❌ Computationally infeasible!\n\n";

        std::cout << "==============================================\n";
        std::cout << "CONCLUSION\n";
        std::cout << "==============================================\n\n";

        std::cout << "❌ FAILED - Cannot decrypt b.ct with only pk.bin\n\n";

        std::cout << "What we CAN do with just pk.bin:\n";
        std::cout << "  ✓ Compute G-sum (but it's meaningless)\n";
        std::cout << "  ✓ See structure (layers, edges)\n";
        std::cout << "  ✓ Recover divisor IF we have ratio (a.ct + divresult.ct)\n\n";

        std::cout << "What we CANNOT do:\n";
        std::cout << "  ✗ Decrypt independent ciphertexts like b.ct\n";
        std::cout << "  ✗ Recover plaintexts from single ciphertexts\n";
        std::cout << "  ✗ Compute R values (need secret key)\n";
        std::cout << "  ✗ Break the encryption\n\n";

        std::cout << "The actual plaintext in b.ct is: 7\n";
        std::cout << "We have NO WAY to recover this without sk.bin!\n\n";

        std::cout << "==============================================\n";
        std::cout << "DIFFERENCE EXPLAINED\n";
        std::cout << "==============================================\n\n";

        std::cout << "What the divisor exploit recovered:\n";
        std::cout << "  ✓ The PUBLIC constant k=7 from ct_div_const(a, 7)\n";
        std::cout << "  ✓ Used ratio: G-sum(a) / G-sum(a/k) = k\n";
        std::cout << "  ✓ Works because SAME R in both ciphertexts\n\n";

        std::cout << "What we CANNOT recover:\n";
        std::cout << "  ✗ The ENCRYPTED value 7 inside b.ct\n";
        std::cout << "  ✗ b.ct has INDEPENDENT R (fresh encryption)\n";
        std::cout << "  ✗ No ratio trick possible\n";
        std::cout << "  ✗ Needs secret key to decrypt\n\n";

        std::cout << "They're both '7' but DIFFERENT:\n";
        std::cout << "  - One is PUBLIC (divisor parameter)\n";
        std::cout << "  - One is ENCRYPTED (hidden in b.ct)\n\n";

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
