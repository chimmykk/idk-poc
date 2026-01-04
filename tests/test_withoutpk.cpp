#include <pvac/pvac.hpp>
#include <iostream>
#include <fstream>

using namespace pvac;

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
}

auto loadCts = [](const std::string& path) -> std::vector<Cipher> {
    std::ifstream i(path, std::ios::binary);
    if (!i || io::get32(i) != Magic::CT || io::get32(i) != 1)
        throw std::runtime_error("bad CT: " + path);
    std::vector<Cipher> cts(io::get64(i));
    for (auto& c : cts) c = ser::getCipher(i);
    return cts;
};

int main() {
    std::cout << "[*] Attempting Analysis (NO PUBLIC KEY)\n\n";

    try {
        Cipher ct_a = loadCts("bounty3_data/a.ct")[0];
        Cipher ct_div = loadCts("bounty3_data/divresult.ct")[0];
        std::cout << "[+] Loaded a.ct and divresult.ct (NO pk.bin!)\n\n";

        std::cout << "--- Structure ---\n";
        std::cout << "a.ct:      L=" << ct_a.L.size() << " E=" << ct_a.E.size() << "\n";
        std::cout << "divresult: L=" << ct_div.L.size() << " E=" << ct_div.E.size() << "\n\n";

        // Check seed match (vulnerability confirmation)
        std::cout << "--- Seed Comparison ---\n";
        bool seeds_match = true;
        for (size_t i = 0; i < ct_a.L.size() && i < ct_div.L.size(); i++) {
            bool match = (ct_a.L[i].seed.ztag == ct_div.L[i].seed.ztag &&
                          ct_a.L[i].seed.nonce.lo == ct_div.L[i].seed.nonce.lo);
            std::cout << "Layer " << i << ": " << (match ? "MATCH" : "DIFFER") << "\n";
            if (!match) seeds_match = false;
        }
        std::cout << "\n";

        if (seeds_match) {
            std::cout << "[!] VULNERABILITY: Seeds are identical!\n";
            std::cout << "[!] This means R values are the same.\n\n";

            // Ratio attack without PK
            std::cout << "--- Ratio Attack (No PK) ---\n";
            Fp w_a = ct_a.E[0].w;
            Fp w_div = ct_div.E[0].w;
            
            // k = w_a / w_div = w_a * inv(w_div)
            Fp k = fp_mul(w_a, fp_inv(w_div));
            
            std::cout << "w_a[0]:   " << w_a.lo << "\n";
            std::cout << "w_div[0]: " << w_div.lo << "\n";
            std::cout << "Ratio k:  " << k.lo << "\n\n";

            std::cout << "[+] Recovered divisor k = " << k.lo << "\n";
        } else {
            std::cout << "[-] Seeds differ, ratio attack not possible.\n";
        }

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
