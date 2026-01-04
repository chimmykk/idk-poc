#include <pvac/pvac.hpp>
#include <cstdint>
#include <string>
#include <vector>
#include <iostream>
#include <fstream>
#include <filesystem>

using namespace pvac;
namespace fs = std::filesystem;

// Format signatures
namespace Magic {
    constexpr uint32_t CT  = 0x66699666;
    constexpr uint32_t SK  = 0x66666999;
    constexpr uint32_t PK  = 0x06660666;
    constexpr uint32_t VER = 1;
}

namespace io {
    auto put32 = [](std::ostream& o, uint32_t x) -> std::ostream& {
        return o.write(reinterpret_cast<const char*>(&x), 4);
    };

    auto put64 = [](std::ostream& o, uint64_t x) -> std::ostream& {
        return o.write(reinterpret_cast<const char*>(&x), 8);
    };

    auto putBv = [](std::ostream& o, const BitVec& b) -> std::ostream& {
        put32(o, (uint32_t)b.nbits);
        for (size_t i = 0; i < (b.nbits + 63) / 64; ++i) put64(o, b.w[i]);
        return o;
    };

    auto putFp = [](std::ostream& o, const Fp& f) -> std::ostream& {
        put64(o, f.lo);
        return put64(o, f.hi);
    };
}

namespace ser {
    using namespace io;

    auto putLayer = [](std::ostream& o, const Layer& L) {
        o.put((uint8_t)L.rule);
        if (L.rule == RRule::BASE) {
            put64(o, L.seed.ztag);
            put64(o, L.seed.nonce.lo);
            put64(o, L.seed.nonce.hi);
        } else if (L.rule == RRule::PROD) {
            put32(o, L.pa);
            put32(o, L.pb);
        } else {
            put64(o, 0); put64(o, 0); put64(o, 0);
        }
    };

    auto putEdge = [](std::ostream& o, const Edge& e) {
        put32(o, e.layer_id);
        o.write(reinterpret_cast<const char*>(&e.idx), 2);
        o.put(e.ch);
        o.put(0);
        putFp(o, e.w);
        putBv(o, e.s);
    };

    auto putCipher = [](std::ostream& o, const Cipher& C) {
        put32(o, (uint32_t)C.L.size());
        put32(o, (uint32_t)C.E.size());
        for (const auto& L : C.L) putLayer(o, L);
        for (const auto& e : C.E) putEdge(o, e);
    };
}

auto saveCt = [](const Cipher& ct, const std::string& path) {
    std::ofstream o(path, std::ios::binary);
    io::put32(o, Magic::CT);
    io::put32(o, Magic::VER);
    io::put64(o, 1); // count = 1
    ser::putCipher(o, ct);
    std::cout << "[OK] Saved: " << path << std::endl;
};

auto savePk = [](const PubKey& pk, const std::string& path) {
    std::ofstream o(path, std::ios::binary);
    io::put32(o, Magic::PK);
    io::put32(o, Magic::VER);
    io::put32(o, pk.prm.m_bits);
    io::put32(o, pk.prm.B);
    io::put32(o, pk.prm.lpn_t);
    io::put32(o, pk.prm.lpn_n);
    io::put32(o, pk.prm.lpn_tau_num);
    io::put32(o, pk.prm.lpn_tau_den);
    io::put32(o, (uint32_t)pk.prm.noise_entropy_bits);
    io::put32(o, (uint32_t)pk.prm.depth_slope_bits);

    // Convert double to uint64_t for serialization
    uint64_t t2_bits;
    memcpy(&t2_bits, &pk.prm.tuple2_fraction, 8);
    io::put64(o, t2_bits);

    io::put32(o, pk.prm.edge_budget);
    io::put64(o, pk.canon_tag);
    o.write(reinterpret_cast<const char*>(pk.H_digest.data()), 32);
    io::put64(o, pk.H.size());
    for (const auto& h : pk.H) io::putBv(o, h);
    io::put64(o, pk.ubk.perm.size());
    for (auto v : pk.ubk.perm) io::put32(o, v);
    io::put64(o, pk.ubk.inv.size());
    for (auto v : pk.ubk.inv) io::put32(o, v);
    io::putFp(o, pk.omega_B);
    io::put64(o, pk.powg_B.size());
    for (const auto& f : pk.powg_B) io::putFp(o, f);
    std::cout << "[OK] Saved: " << path << std::endl;
};

auto saveSk = [](const SecKey& sk, const std::string& path) {
    std::ofstream o(path, std::ios::binary);
    io::put32(o, Magic::SK);
    io::put32(o, Magic::VER);
    for (int j = 0; j < 4; ++j) io::put64(o, sk.prf_k[j]);
    io::put64(o, sk.lpn_s_bits.size());
    for (auto w : sk.lpn_s_bits) io::put64(o, w);
    std::cout << "[OK] Saved: " << path << std::endl;
};

int main() {
    std::cout << "Creating Division Test Files" << std::endl;
    std::cout << "================================" << std::endl;

    // Create output directory
    const std::string dir = "bounty3_data";
    fs::create_directories(dir);

    // Generate keys
    std::cout << "\nGenerating keys..." << std::endl;
    Params prm;
    PubKey pk;
    SecKey sk;
    keygen(prm, pk, sk);
    std::cout << "Keys generated" << std::endl;

    // Values
    uint64_t a_val = 5;
    uint64_t b_val = 7;

    std::cout << "\nEncrypting values..." << std::endl;
    std::cout << "  a = " << a_val << std::endl;
    std::cout << "  b = " << b_val << " (divisor)" << std::endl;

    // Encrypt a = 5
    Cipher a_ct = enc_value(pk, sk, a_val);
    std::cout << "Encrypted a = 5" << std::endl;

    // Encrypt b = 7 (for reference)
    Cipher b_ct = enc_value(pk, sk, b_val);
    std::cout << "Encrypted b = 7" << std::endl;

    // Perform division: result = a / b = 5 / 7
    std::cout << "\nPerforming division: a / b = 5 / 7" << std::endl;
    Cipher divresult_ct = ct_div_const(pk, a_ct, fp_from_u64(b_val));
    std::cout << "Division complete" << std::endl;

    // Verify the result
    std::cout << "\nVerification:" << std::endl;
    Fp dec_a = dec_value(pk, sk, a_ct);
    Fp dec_b = dec_value(pk, sk, b_ct);
    Fp dec_div = dec_value(pk, sk, divresult_ct);

    std::cout << "  Decrypted a: " << dec_a.lo << std::endl;
    std::cout << "  Decrypted b: " << dec_b.lo << std::endl;
    std::cout << "  Decrypted result: " << dec_div.lo << std::endl;

    // Compute expected: 5 / 7 in the field
    Fp expected = fp_mul(fp_from_u64(a_val), fp_inv(fp_from_u64(b_val)));
    std::cout << "  Expected (5/7 in field): " << expected.lo << std::endl;

    if (ct::fp_eq(dec_div, expected)) {
        std::cout << "Division verified correct!" << std::endl;
    } else {
        std::cout << "Division verification failed!" << std::endl;
    }

    // Save files
    std::cout << "\nSaving files to " << dir << "/" << std::endl;
    savePk(pk, dir + "/pk.bin");
    saveSk(sk, dir + "/sk.bin");
    saveCt(a_ct, dir + "/a.ct");
    saveCt(b_ct, dir + "/b.ct");
    saveCt(divresult_ct, dir + "/divresult.ct");

    // Print structure info
    std::cout << "\nStructure Information:" << std::endl;
    std::cout << "  a.ct: " << a_ct.L.size() << " layers, " << a_ct.E.size() << " edges" << std::endl;
    std::cout << "  divresult.ct: " << divresult_ct.L.size() << " layers, " << divresult_ct.E.size() << " edges" << std::endl;

    std::cout << "\nAll files created successfully!" << std::endl;
    std::cout << "\nFiles created:" << std::endl;
    std::cout << "  - " << dir << "/pk.bin (public key)" << std::endl;
    std::cout << "  - " << dir << "/sk.bin (secret key)" << std::endl;
    std::cout << "  - " << dir << "/a.ct (encryption of 5)" << std::endl;
    std::cout << "  - " << dir << "/b.ct (encryption of 7)" << std::endl;
    std::cout << "  - " << dir << "/divresult.ct (5/7 result)" << std::endl;

    std::cout << "\nDivisor that should be recovered: " << b_val << std::endl;

    return 0;
}
