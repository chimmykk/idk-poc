#include <iostream>
#include <fstream>
#include <chrono>
#include <vector>
#include <pvac/pvac.hpp>

using namespace pvac;
using Clock = std::chrono::high_resolution_clock;

static long long us_diff(const Clock::time_point& a, const Clock::time_point& b) {
    return std::chrono::duration_cast<std::chrono::microseconds>(b - a).count();
}

struct ScenarioCfg { const char* label; int steps; };

static void run_scenario(const ScenarioCfg& cfg, int scenario_id,
                         const PubKey& pk, const SecKey& sk, std::ofstream& csv) {
    constexpr int pool_size = 8;
    constexpr int max_mul_depth = 4;

    std::vector<Fp> pool_fp(pool_size);
    std::vector<Cipher> pool_ct(pool_size);

    for (int i = 0; i < pool_size; ++i) {
        uint64_t x = (csprng_u64() % 100000u) + 1u;
        pool_fp[i] = fp_from_u64(x);
        pool_ct[i] = enc_value(pk, sk, x);
    }

    Cipher acc = pool_ct[0];
    Fp val = pool_fp[0];
    int mul_depth = 0;

    for (int step = 1; step <= cfg.steps; ++step) {
        uint64_t r = csprng_u64();
        int op = (int)(r % 3u);
        int idx = (int)((r >> 8) % pool_size);

        const Cipher& B = pool_ct[idx];
        const Fp& vb = pool_fp[idx];

        auto t0 = Clock::now();
        if (op == 0) {
            acc = ct_add(pk, acc, B);
            val = fp_add(val, vb);
        } else if (op == 1) {
            acc = ct_sub(pk, acc, B);
            val = fp_sub(val, vb);
        } else if (mul_depth < max_mul_depth) {
            acc = ct_mul(pk, acc, B);
            val = fp_mul(val, vb);
            ++mul_depth;
        } else {
            acc = ct_add(pk, acc, B);
            val = fp_add(val, vb);
        }
        auto t1 = Clock::now();

        auto t2 = Clock::now();
        Fp dec = dec_value(pk, sk, acc);
        auto t3 = Clock::now();

        csv << cfg.label << "," << scenario_id << "," << step << ","
            << acc.E.size() << "," << acc.L.size() << ","
            << sigma_density(pk, acc) << "," << sigma_shannon(acc) << ","
            << us_diff(t0, t1) << "," << us_diff(t2, t3) << ","
            << (ct::fp_eq(dec, val) ? 1 : 0) << "\n";
    }
}

int main() {
    std::cout << "- sigma stress test -\n";

    Params prm; PubKey pk; SecKey sk;
    keygen(prm, pk, sk);

    std::ofstream csv("pvac_sigma.csv", std::ios::out | std::ios::trunc);
    if (!csv) { std::cerr << "cannot open pvac_sigma.csv\n"; return 1; }

    csv << "mode,scenario,step,edges,layers,balance,sigma_H,op_us,dec_us,ok\n";

    ScenarioCfg cfgs[] = {{"short", 16}, {"medium", 64}, {"long", 128}};

    for (int i = 0; i < 3; ++i) {
        run_scenario(cfgs[i], i, pk, sk, csv);
        csv.flush();
    }

    std::cout << "sigma stress done\n";
    return 0;
}