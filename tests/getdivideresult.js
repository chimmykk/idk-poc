

const p = 2n ** 64n - 1n;


function mulMod(a, b) {
  return ((a % p) * (b % p)) % p;
}

function recoverDividend(divResult, divisor) {
  return mulMod(divResult, divisor);
}

const divisor = 7n;
const divResult = 5270498306774157605n;

const recovered = recoverDividend(divResult, divisor);


console.log("p =", p.toString());
console.log("");
console.log("Given:");
console.log("  divisor =", divisor.toString());
console.log("   =", divResult.toString());
console.log("");
console.log("Recovered dividend:", recovered.toString());
console.log("");
console.log("Verification: divResult × divisor mod p =", recovered.toString());