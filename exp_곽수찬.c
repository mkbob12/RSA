
#include <stdio.h>
#include <openssl/bn.h>




int ExpMod(BIGNUM *r, const BIGNUM *a, const BIGNUM *e, BIGNUM *m){

    int result = 0;
    BIGNUM *c = BN_new();
    BIGNUM *i = BN_new();
    BIGNUM *one = BN_new();

    BN_one(one); // Initialize 'one' to 1

    BN_set_word(c,1);
    BN_set_word(i,1);

    //BN_copy(c, a); // Initialize 'c' to 'a'

    BN_CTX *ctx = BN_CTX_new();
    if (ctx == NULL) {
        result = -1; // Failed to initialize BN_CTX
        BN_free(c);
        BN_free(i);
        BN_free(one);
        return result;
    }

    for (i; BN_cmp(i, e) <= 0; BN_add(i, i, one)) {
        BN_mul(c, c, a, ctx); // c = c * a
    }

    BN_mod(r, c, m, ctx);

    BN_CTX_free(ctx);
    BN_free(c);
    BN_free(i);
    BN_free(one);

    return result;
};

void printBN(char *msg, BIGNUM * a)
{
        char * number_str = BN_bn2dec(a);
        printf("%s %s\n", msg, number_str);
        OPENSSL_free(number_str);
};

int main (int argc, char *argv[])
{
        BIGNUM *a = BN_new();
        BIGNUM *e = BN_new();
        BIGNUM *m = BN_new();
        BIGNUM *res = BN_new();

        if(argc != 4){
                printf("usage: exp base exponent modulus\n");
                return -1;
        }

        BN_dec2bn(&a, argv[1]);
        BN_dec2bn(&e, argv[2]);
        BN_dec2bn(&m, argv[3]);
        printBN("a = ", a);
        printBN("e = ", e);
        printBN("m = ", m);

        ExpMod(res,a,e,m);

        printBN("a**e mod m = ", res);

        if(a != NULL) BN_free(a);
        if(e != NULL) BN_free(e);
        if(m != NULL) BN_free(m);
        if(res != NULL) BN_free(res);

        return 0;
}

