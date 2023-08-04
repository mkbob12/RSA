
#include <stdio.h>
#include <openssl/bn.h>




int ExpMod(BIGNUM *r, const BIGNUM *a, const BIGNUM *e, BIGNUM *m){
    int result = 0;
    BN_CTX *ctx = NULL;

    // BIGNUM 생성
    ctx = BN_CTX_new();
    if (ctx == NULL) {
        result = -1;
        goto cleanup;
    }

    // 모듈러 거듭제곱 계산 
    if (BN_mod_exp(r, a, e, m, ctx) != 1) {
        result = -1;
        goto cleanup;
    }

    result = 1;

cleanup:
    if (ctx) {
        BN_CTX_free(ctx);
    }

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

