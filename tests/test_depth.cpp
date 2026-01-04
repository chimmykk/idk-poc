#include <iostream>
#include <fstream>
#include <chrono>
#include <pvac/pvac.hpp>

using namespace pvac;
using Clock = std::chrono::high_resolution_clock;

static long long us_diff(const Clock::time_point& a, const Clock::time_point& b) {
    return std::chrono::duration_cast<std::chrono::microseconds>(b - a).count();
}

static void debug_sigma(const char* label, const Cipher& c) {
    std::cout << "[debug] " << label << ":\n";
    if (c.E.empty()) { std::cout << "  (no edges)\n"; return; }
    
    size_t popcnt = 0, bits = 0;
    for (const auto& e : c.E) { popcnt += e.s.popcnt(); bits += e.s.nbits; }
    
    std::cout << "edges = " << c.E.size() << " layers = " << c.L.size()
              << " popcnt = " << popcnt << " bits = " << bits
              << " ratio = " << (bits > 0 ? (double)popcnt / bits : 0) << "\n";
}

int main() {
    std::cout << "- depth stress test -\n";

    Params prm; PubKey pk; SecKey sk;
    keygen(prm, pk, sk);

    std::ofstream csv("pvac_depth.csv", std::ios::out | std::ios::trunc);
    if (!csv) { std::cerr << "cannot open depth.csv\n"; return 1; }

    csv << "mode, step, edges, layers, balance, sigma_H, mul_us, dec_us, ok\n";

    Cipher c = enc_value(pk, sk, 2);
    Fp expected = fp_from_u64(2);

    debug_sigma("fresh enc_value(2)", c);
    std::cout << "\n[plain] chain c <- c*c\n";

    constexpr int max_steps = 10;

    for (int step = 1; step <= max_steps; ++step) {
        auto t0 = Clock::now();
        c = ct_mul(pk, c, c);
        auto t1 = Clock::now();

        expected = fp_mul(expected, expected);

        auto t2 = Clock::now();
        Fp dec = dec_value(pk, sk, c);
        auto t3 = Clock::now();

        bool ok = ct::fp_eq(dec, expected);
        double bal = sigma_density(pk, c);
        double sH = sigma_shannon(c);
        long long mul_us = us_diff(t0, t1);
        long long dec_us = us_diff(t2, t3);

        if (step == 1) debug_sigma("after first mul", c);

        std::cout << "step = " << step << " edges = " << c.E.size() << " layers = " << c.L.size()
                  << " dens = " << bal << " sH = " << sH
                  << " mul_ms = " << (mul_us / 1000.0) << " dec_ms = " << (dec_us / 1000.0)
                  << "" << (ok ? " ok" : "FAIL") << "\n";

        csv << "plain," << step << "," << c.E.size() << "," << c.L.size() << ","
            << bal << "," << sH << "," << mul_us << "," << dec_us << "," << (ok ? 1 : 0) << "\n";

        csv.flush();
    }

    return 0;
}