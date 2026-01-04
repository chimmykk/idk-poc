

const p = 2n ** 64n - 1n;


function mulMod(a, b) {
  return ((a % p) * (b % p)) % p;
}

function recoverDividend(divResult, divisor) {
  return mulMod(divResult, divisor);
}

const divisor = 7n;
const divResult = 5270498306774157605n; // consider this is public
// exaple this is a rewards points

// so if a game mech follow a trick like
// some random number * divisor = reward(divResult)
// then we recover the divisor 



const recovered = recoverDividend(divResult, divisor);

// this recovered the value
// then follow the inverse operation we ca compute
// the value of a(which is the hidden ratio or points)
console.log("p =", p.toString());
console.log("");
console.log("Given:");
console.log("  divisor =", divisor.toString());
console.log("   =", divResult.toString());
console.log("");
console.log("Recovered dividend:", recovered.toString());
console.log("");
console.log("Verification: divResult × divisor mod p =", recovered.toString());