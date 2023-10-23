/* bn_sample.c */
#include <stdio.h>
#include <openssl/bn.h>
#define NBITS 256
void printBN(char *msg, BIGNUM * a)
{
/* Use BN_bn2hex(a) for hex string
* Use BN_bn2dec(a) for decimal string */
char * number_str = BN_bn2hex(a);
printf("%s %s\n", msg, number_str);
OPENSSL_free(number_str);
}
int main ()
{
BN_CTX *ctx = BN_CTX_new();
BIGNUM *n = BN_new();
BIGNUM *e = BN_new();
BIGNUM *M = BN_new();
BIGNUM *d = BN_new();
BIGNUM *cipher = BN_new();

// Initialize p,q,e
BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
//From CMD python python3 -c 'import binascii; print(binascii.hexlify("CSLesley".encode()).decode())'
BN_hex2bn(&M, "43534c65736c6579");
BN_hex2bn(&e, "010001");

//find cipher
BN_mod_exp(cipher, M, e, n, ctx);

printBN("ciphertext: ", cipher);
return 0;
}
