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
    constexpr uint32_t SK = 0x66666999;
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

auto loadSk = [](const std::string& path) -> SecKey {
    std::ifstream i(path, std::ios::binary);
    if (!i || io::get32(i) != Magic::SK || io::get32(i) != Magic::VER)
        throw std::runtime_error("bad SK: " + path);
    SecKey sk;
    for (int j = 0; j < 4; ++j) sk.prf_k[j] = io::get64(i);
    sk.lpn_s_bits.resize(io::get64(i));
    for (auto& w : sk.lpn_s_bits) w = io::get64(i);
    return sk;
};

int main() {
    std::cout << "==============================================\n";
    std::cout << "Decrypting bounty3_data Ciphertexts\n";
    std::cout << "==============================================\n\n";

    try {
        // Load keys
        std::cout << "📥 Loading keys...\n";
        PubKey pk = loadPk("bounty3_data/pk.bin");
        SecKey sk = loadSk("bounty3_data/sk.bin");
        std::cout << "✅ Keys loaded\n\n";

        // Load ciphertexts
        std::cout << "📥 Loading ciphertexts...\n";
        Cipher ct_a = loadCts("bounty3_data/a.ct")[0];
        Cipher ct_b = loadCts("bounty3_data/b.ct")[0];
        Cipher ct_div = loadCts("bounty3_data/divresult.ct")[0];
        std::cout << "✅ Ciphertexts loaded\n\n";

        // Decrypt all
        std::cout << "🔓 Decrypting...\n";
        std::cout << "================\n\n";

        Fp dec_a = dec_value(pk, sk, ct_a);
        Fp dec_b = dec_value(pk, sk, ct_b);
        Fp dec_div = dec_value(pk, sk, ct_div);

        // Display results
        std::cout << "📊 PLAINTEXT VALUES:\n";
        std::cout << "====================\n\n";

        std::cout << "a.ct decrypts to:\n";
        std::cout << "  Decimal: " << dec_a.lo << "\n";
        std::cout << "  Hex: 0x" << std::hex << dec_a.lo << std::dec << "\n";
        std::cout << "  Field element: (lo=" << dec_a.lo << ", hi=" << dec_a.hi << ")\n\n";

        std::cout << "b.ct decrypts to:\n";
        std::cout << "  Decimal: " << dec_b.lo << "\n";
        std::cout << "  Hex: 0x" << std::hex << dec_b.lo << std::dec << "\n";
        std::cout << "  Field element: (lo=" << dec_b.lo << ", hi=" << dec_b.hi << ")\n\n";

        std::cout << "divresult.ct decrypts to:\n";
        std::cout << "  Decimal: " << dec_div.lo << "\n";
        std::cout << "  Hex: 0x" << std::hex << dec_div.lo << std::dec << "\n";
        std::cout << "  Field element: (lo=" << dec_div.lo << ", hi=" << dec_div.hi << ")\n\n";

        // Verify relationships
        std::cout << "🔍 VERIFICATION:\n";
        std::cout << "================\n\n";

        // Compute 5/7 in the field
        Fp expected = fp_mul(fp_from_u64(5), fp_inv(fp_from_u64(7)));
        std::cout << "Expected (5/7 in field): " << expected.lo << "\n";

        if (ct::fp_eq(dec_div, expected)) {
            std::cout << "✅ divresult.ct = 5/7 (CORRECT)\n\n";
        } else {
            std::cout << "❌ divresult.ct ≠ 5/7 (ERROR)\n\n";
        }

        // Verify: divresult * 7 = 5
        Fp verify = fp_mul(dec_div, fp_from_u64(7));
        std::cout << "Verify: divresult × 7 = " << verify.lo << "\n";

        if (ct::fp_eq(verify, fp_from_u64(5))) {
            std::cout << "✅ divresult × 7 = 5 (CORRECT)\n\n";
        } else {
            std::cout << "❌ divresult × 7 ≠ 5 (ERROR)\n\n";
        }

        std::cout << "==============================================\n";
        std::cout << "SUMMARY\n";
        std::cout << "==============================================\n\n";
        std::cout << "a.ct contains: " << dec_a.lo << " (plaintext 5)\n";
        std::cout << "b.ct contains: " << dec_b.lo << " (plaintext 7)\n";
        std::cout << "divresult.ct contains: " << dec_div.lo << " (plaintext 5/7)\n";
        std::cout << "\nNote: divresult = ct_div_const(pk, a, 7)\n";
        std::cout << "      where 7 is a PLAINTEXT constant (not b.ct)\n\n";

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
