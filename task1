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
BIGNUM *p = BN_new();
BIGNUM *q = BN_new();
BIGNUM *e = BN_new();
BIGNUM *p_minus_one = BN_new();
BIGNUM *q_minus_one = BN_new();
BIGNUM *res = BN_new();
BIGNUM *phi = BN_new();
BIGNUM *key = BN_new();

// Initialize p,q,e
BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
BN_hex2bn(&e, "0D88C3");

//Find n
BN_mul(res, p, q, ctx);

//Find phi (p-1)*(q-1)
BN_sub(q_minus_one, q, BN_value_one());
BN_sub(p_minus_one, p, BN_value_one());
BN_mul(phi, q_minus_one, p_minus_one, ctx);

//find private key
BN_mod_inverse(key,e, phi, ctx);

printBN("private key d= ", key);
return 0;
}
