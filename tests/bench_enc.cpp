#include <pvac/pvac.hpp>
#include <chrono>
#include <iostream>

using namespace pvac;
using Clock = std::chrono::steady_clock;

int main() {
    Params prm;
    PubKey pk;
    SecKey sk;
    keygen(prm, pk, sk);
    
    std::cout << "- params - \n";
    std::cout << "B: " << pk.prm.B << "\n";
    std::cout << "lpn_t: " << pk.prm.lpn_t << "\n";
    std::cout << "lpn_n: " << pk.prm.lpn_n << "\n";
    std::cout << "err_wt: " << pk.prm.err_wt << "\n";
    
    std::cout << "\n- single prf_R -\n";
    RSeed seed;
    seed.nonce = make_nonce128();
    seed.ztag = prg_layer_ztag(pk.canon_tag, seed.nonce);
    
    auto t0 = Clock::now();
    Fp r = prf_R(pk, sk, seed);
    auto t1 = Clock::now();
    std::cout << "prf_R: " << std::chrono::duration<double>(t1-t0).count() << "s\n";
    
    std::cout << "\n- enc_value -\n";
    t0 = Clock::now();
    Cipher c = enc_value(pk, sk, 42);
    t1 = Clock::now();
    std::cout << "enc_value: " << std::chrono::duration<double>(t1-t0).count() << "s\n";
    std::cout << "edges: " << c.E.size() << "\n";
    std::cout << "layers: " << c.L.size() << "\n";
    
    return 0;
}