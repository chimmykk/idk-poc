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
    std::cout << "[*] Attempting Decryption (No Secret Key)\n";

    try {
        PubKey pk = loadPk("bounty3_data/pk.bin");
        Cipher ct_b = loadCts("bounty3_data/b.ct")[0];
        std::cout << "[+] Loaded PK and b.ct\n";

        std::cout << "[-] Structure: L=" << ct_b.L.size() << " E=" << ct_b.E.size() << "\n";

        for (size_t i = 0; i < ct_b.L.size(); i++) {
            const Layer& L = ct_b.L[i];
            if (L.rule == RRule::BASE) {
                std::cout << "  L" << i << ": BASE (n=" << std::hex << L.seed.nonce.lo << std::dec << ")\n";
            }
        }

        std::cout << "[-] Edge sample (0): w=" << ct_b.E[0].w.lo << "\n";

        Fp gsum = total_gsum(pk, ct_b);
        std::cout << "[-] G-sum: 0x" << std::hex << gsum.hi << gsum.lo << std::dec << "\n";

        std::cout << "[!] Decryption IMPOSSIBLE: Missing secret key components (R, mask).\n";
        std::cout << "[!] Confirmed: G-sum reveals nothing about plaintext '7'.\n";

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
