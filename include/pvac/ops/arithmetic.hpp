#pragma once

#include <cstdint>
#include <vector>
#include <unordered_map>

#include "../core/types.hpp"
#include "encrypt.hpp"

namespace pvac {

inline Cipher ct_add(const PubKey& pk, const Cipher& A, const Cipher& B) {
    Cipher C;
    C.L.reserve(A.L.size() + B.L.size());
    C.E.reserve(A.E.size() + B.E.size());
    
    for (const auto& L : A.L) C.L.push_back(L);
    uint32_t off = (uint32_t)A.L.size();
    
    for (auto L : B.L) {
        if (L.rule == RRule::PROD) { L.pa += off; L.pb += off; }
        C.L.push_back(L);
    }
    
    for (const auto& e : A.E) C.E.push_back(e);
    for (auto e : B.E) { e.layer_id += off; C.E.push_back(std::move(e)); }
    
    guard_budget(pk, C, "add");
    compact_layers(C);
    return C;
}

inline Cipher ct_scale(const PubKey&, const Cipher& A, const Fp& s) {
    Cipher C = A;
    for (auto& e : C.E) e.w = fp_mul(e.w, s);
    return C;
}

inline Cipher ct_neg(const PubKey& pk, const Cipher& A) {
    return ct_scale(pk, A, fp_neg(fp_from_u64(1)));
}

inline Cipher ct_sub(const PubKey& pk, const Cipher& A, const Cipher& B) {
    return ct_add(pk, A, ct_neg(pk, B));
}

inline Cipher ct_mul(const PubKey& pk, const Cipher& A, const Cipher& B) {
    Cipher C;
    
    for (const auto& L : A.L) C.L.push_back(L);
    uint32_t off = (uint32_t)C.L.size();
    uint32_t LA = (uint32_t)A.L.size(), LB = (uint32_t)B.L.size();
    
    for (auto L : B.L) {
        if (L.rule == RRule::PROD) { L.pa += off; L.pb += off; }
        C.L.push_back(L);
    }
    
    uint32_t base = (uint32_t)C.L.size();
    for (uint32_t la = 0; la < LA; ++la) {
        for (uint32_t lb = 0; lb < LB; ++lb) {
            Layer L;
            L.rule = RRule::PROD;
            L.pa = la;
            L.pb = off + lb;
            L.seed.nonce = make_nonce128();
            L.seed.ztag = prg_layer_ztag(pk.canon_tag, L.seed.nonce);
            C.L.push_back(L);
        }
    }
    
    struct Agg { Fp wp{}, wm{}; bool ip = false, im = false; };
    struct H { size_t operator()(uint64_t x) const noexcept { return x * 0x9E3779B97F4A7C15ull; } };
    
    std::unordered_map<uint64_t, Agg, H> acc;
    acc.reserve(A.E.size() * B.E.size());
    int Bmod = pk.prm.B;
    
    for (const auto& ea : A.E) {
        for (const auto& eb : B.E) {
            uint64_t k = ((uint64_t)(ea.layer_id * LB + eb.layer_id) << 32) | ((ea.idx + eb.idx) % Bmod);
            Agg& a = acc[k];
            Fp ww = fp_mul(ea.w, eb.w);
            (ea.ch == eb.ch)
                ? (a.ip || (a.wp = fp_from_u64(0), a.ip = true), a.wp = fp_add(a.wp, ww))
                : (a.im || (a.wm = fp_from_u64(0), a.im = true), a.wm = fp_add(a.wm, ww));
        }
    }
    
    auto emit = [&](uint32_t lid, uint16_t idx, uint8_t ch, const Fp& w) {
        const Layer& Lp = C.L[lid];
        C.E.push_back(Edge{lid, idx, ch, w,
            sigma_from_H(pk, Lp.seed.ztag, Lp.seed.nonce, idx, ch, csprng_u64())});
    };
    
    for (const auto& [k, a] : acc) {
        uint32_t lid = base + (uint32_t)(k >> 32);
        uint16_t idx = (uint16_t)(k & 0xFFFF);
        if (a.ip && ct::fp_is_nonzero(a.wp)) emit(lid, idx, SGN_P, a.wp);
        if (a.im && ct::fp_is_nonzero(a.wm)) emit(lid, idx, SGN_M, a.wm);
    }
    
    guard_budget(pk, C, "mul");
    compact_layers(C);
    return C;
}

inline Cipher ct_div_const(const PubKey& pk, const Cipher& A, const Fp& k) {
    return ct_scale(pk, A, fp_inv(k));
}

}