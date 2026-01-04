# **mini‑bounty challenge v2**
the challenge consists of taking two ciphertexts, `a.ct` and `b.ct` (obtained using file `bounty2_test.cpp` in the tests folder), performing a homomorphic addition operation* on the two ciphertexts, obtaining the resulting sum of this addition, and then solving or finding an error in the implementation of the addition or encryption functions that will lead to information leakage.

** an example of such an operation is located in the same folder and is called `add.cpp`, you can use it as an analyzer and debugger for experimenting directly with the addition and testing your hypotheses.

if you succeed, you **will need** to create a [new issue](https://github.com/octra-labs/pvac_hfhe_cpp/issues/new) to this repository with the **bounty** label and publish your research that allowed you to access the information, regardless of whether you crack two ciphertexts or the resulting ciphertext with the sum, and can provide the resulting number, you are eligible to immediately claim a payment of $3333.3333 in USDT, which is currently located at the address: [0x7d7d0d882bd19286d89bD036C2A37C6E0f497B2D](https://etherscan.io/address/0x7d7d0d882bd19286d89bd036c2a37c6e0f497b2d).

the first person to submit an issue ticket report in this repository with the correct result (the sum of the two ciphertexts) and an explanation of how it was done will immediately receive access to the reward funds.

as usual, potentially useful information is located in the `tests` folder, and the working files are in the `bounty2_data` folder.

*please read the text above carefully and follow the rules so we can accurately determine the winner, the first challenge ended with several people simultaneously claiming victory.

ultimately, we were unable to determine the true winner, and one of those few participants simply quietly took the money without publishing their research, **this is not a good practice**, if you manage to carry out an attack, for the sake of public interest and transparency, please provide a public explanation.*

***p.s.: in this challenge, we know of at least two points through which you can uncover the solution. ***

you don't need to run `bounty2_test.cpp`, the artifacts are already given and you should work only with them, you should attack `a.ct` or `b.ct`, or the sum ciphertext `a.ct` & `b.ct`:
```
d0ff06b235917a2ca428ebb84f22300baace6b7ff114409435a1278d731c54d5  README.md
3bfb5f3415236435ed0e406fec30f934e1ce30574faaa0954ed794da0c6a96c4  a.ct
e94df1c8597ef34895e2175b7567f19ff081c7f517967fec0ee7bfef1a602ecb  b.ct
692ea043daf5d8910a216a0cff80131fa6a06fe0133ac0f0b91a0f0570378877  params.json
83ee5ec9368bfcce58e410508c6b8e1d1710873eeb21f239b7c860f86c5df413  pk.bin
```
good luck to you.