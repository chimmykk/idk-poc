#include <pvac/crypto/lpn.hpp>

#include <cstdint>
#include <cstring>
#include <cassert>
#include <iostream>

using namespace pvac;

int main() {
    std::cout << "- aes ctr test -\n";

#if PVAC_USE_AESNI
    std::cout << "impl = aes-ni\n";

    // FIPS-197 AES-256 test key
    uint8_t key[32] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
    };

    AesCtr256 prg;
    prg.init(key, 0);

    // fill_u64
    uint64_t out[2];
    prg.fill_u64(out, 2);

    std::cout << "block0: " << std::hex 
              << out[0] << " " << out[1] << std::dec << "\n";

    // fill vs next
    prg.init(key, 0);
    uint64_t v1 = prg.next_u64();
    uint64_t v2 = prg.next_u64();

    assert(v1 == out[0]);
    assert(v2 == out[1]);
    std::cout << "consistency: ok\n";

    // stress test
    prg.init(key, 0);
    const int N = 10000;
    uint64_t acc = 0;
    for (int i = 0; i < N; ++i) {
        acc ^= prg.next_u64();
    }
    volatile uint64_t sink = acc;
    (void)sink;

    // nonce separation
    prg.init(key, 1);
    uint64_t diff_v1 = prg.next_u64();
    assert(diff_v1 != v1);
    std::cout << "nonce separation: ok\n";

    // key separation
    uint8_t key2[32];
    std::memcpy(key2, key, 32);
    key2[0] ^= 1;

    AesCtr256 prg2;
    prg2.init(key2, 0);
    uint64_t diff_k1 = prg2.next_u64();
    assert(diff_k1 != v1);
    std::cout << "key separation: ok\n";

    prg.init(key, 42);
    for (int i = 0; i < 1000; ++i) {
        uint64_t b = prg.bounded(100);
        assert(b < 100);
    }
    std::cout << "bounded: ok\n";

    std::cout << "PASS\n";
#else
    std::cout << "skipped (no AES-NI)\n";
#endif

    return 0;
}