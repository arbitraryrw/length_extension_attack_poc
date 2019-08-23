# Length Extension Attack POC

A very basic illustration of how one of the many hash functions built on Merkle-Damgård construction is vulnerable to Length Extension attacks. Specifically, this relates to misusing Merkle-Damgård based hashes as Message Authentication Codes (MAC) H(secret||message).

For the purposes of this project, MD5 was chosen, however, SHA-1 and SHA-2 are also susceptible to this attack. This is purely for educational purposes, however, [hashpump](https://github.com/bwall/HashPump) provides a great tool for performing LE attacks.