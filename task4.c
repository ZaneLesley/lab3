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
BIGNUM *M1 = BN_new(); 
BIGNUM *M2 = BN_new(); 
BIGNUM *d = BN_new();
BIGNUM *signature1 = BN_new();
BIGNUM *signature2 = BN_new();

BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
//From CMD python python3 -c 'import binascii; print(binascii.hexlify("CSLesley".encode()).decode())' + money problem (I owe Lesley $100, and $110.
BN_hex2bn(&M1, "49206f7765204c65736c65792024313030");
BN_hex2bn(&M2, "49206f7765204c65736c65792024313130");

BN_hex2bn(&e, "010001");
BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");

//Sign
BN_mod_exp(signature1, M1, d, n, ctx);
BN_mod_exp(signature2, M2, d, n, ctx);

printBN("Signature of the first message: ", signature1);
printBN("Signature of the second message: ", signature2);
return 0;
}
