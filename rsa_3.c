#include <stdio.h>
#include <openssl/bn.h>
#include <string.h>
void print_BN(char *msg, BIGNUM * a)
{
        char * number_str = BN_bn2dec(a);
        printf("%s %s\n", msg, number_str);
        OPENSSL_free(number_str);
}
void Xeuclid(BIGNUM *a, BIGNUM *b, BIGNUM *x, BIGNUM *y)
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *mul1 = BN_new();
    BIGNUM *mul2 = BN_new();
    BIGNUM *quo = BN_new();
    BIGNUM *remain = BN_new();
    BIGNUM *s0 = BN_new();
    BIGNUM *s1 = BN_new();
    BIGNUM *t0 = BN_new();
    BIGNUM *t1 = BN_new();
    BIGNUM *tmp = BN_new();
    BN_set_word(remain, 1);
    BN_set_word(s0, 1);
    BN_set_word(s1, 0);
    BN_set_word(t0, 0);
    BN_set_word(t1, 1);
    print_BN("e: ",a);
    while(!BN_is_zero(b))
    {
        BN_div(quo,remain,a,b,ctx);

        BN_copy(a, b);
        BN_copy(b, remain);

        BN_copy(tmp,s0);
        BN_mul(mul1,quo,t0,ctx);
        BN_sub(s0,tmp,mul1);

        BN_copy(tmp,s1);
        BN_mul(mul2,quo,t1,ctx);
        BN_sub(s1,tmp,mul2);

        BN_swap(s0,t0);
        BN_swap(s1,t1);
    }
    if (BN_is_negative(s0)) {
        BN_set_negative(s0, 0);
    }
    BN_copy(x, s0);
    BN_copy(y, s1);

    //e의 역원인 x를 d에 넣는다
    
}

int ExpMod(BIGNUM *r, const BIGNUM *a, const BIGNUM *e, BIGNUM *m)
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *i = BN_new();
    BIGNUM *tmp = BN_new();
    BIGNUM *one = BN_new();
    BIGNUM *a1 = BN_new();
    BN_set_word(i,2);
    BN_set_word(one,1);
    BN_copy(a1,a);
    
    for(i;BN_cmp(i,e)==0;BN_add(i,i,one))
    {
        BN_mul(tmp,a1,a,ctx);
        BN_copy(a1,tmp);
    
    }
    
    BN_mod(r,a1,m,ctx);  
    
    // 변경: 할당된 객체를 해제하세요
    BN_CTX_free(ctx);
    BN_free(i);
    BN_free(tmp);
    BN_free(one);
    BN_free(a1);
    
    // 변경: 함수 실행이 성공했음을 나타내는 정수 값을 반환하세요.
    return 1;
}

typedef struct _b12rsa_st {
    BIGNUM *e;
    BIGNUM *d;
    BIGNUM *n;
}BOB12_RSA;

BOB12_RSA *BOB12_RSA_new() {
    BOB12_RSA *rsa = (BOB12_RSA *)malloc(sizeof(BOB12_RSA));
    if (rsa == NULL) {
        return NULL;
    }
    
    rsa->e = BN_new();
    rsa->d = BN_new();
    rsa->n = BN_new();
    return rsa;
}

void BOB12_RSA_free(BOB12_RSA *rsa) {
    if (rsa) {
        BN_free(rsa->e);
        BN_free(rsa->d);
        BN_free(rsa->n);
        free(rsa);
    }
}


void PrintUsage()
{
    printf("usage: rsa [-k|-e e n plaintext|-d d n ciphertext]\n");
}

int BOB12_RSA_Enc(BIGNUM *c, BIGNUM *m, BOB12_RSA *b12rsa)
{
    
    ExpMod(c, m, b12rsa->e, b12rsa->n);
    if (BN_is_zero(c) == 0)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

int BOB12_RSA_Dec(BIGNUM *m, BIGNUM *c, BOB12_RSA *b12rsa)
{
    ExpMod(m, c, b12rsa->d, b12rsa->n);

    if (BN_is_zero(m) == 0)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}



int BOB12_RSA_KeyGen(BOB12_RSA *b12rsa, int nBits)
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    BIGNUM *quo = BN_new();
   BIGNUM *remain = BN_new();
    BIGNUM *s0 = BN_new();
    BIGNUM *s1 = BN_new();
    BIGNUM *t0 = BN_new();
    BIGNUM *t1 = BN_new();
    BIGNUM *tmp = BN_new();
    BIGNUM *mul1 = BN_new();
    BIGNUM *mul2 = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *p = BN_new();
    BIGNUM *p2 = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *q2 = BN_new();
    BIGNUM *phin = BN_new();
    BIGNUM *one = BN_new();
    BN_set_word(remain, 1);
    BN_set_word(s0, 1);
    BN_set_word(s1, 0);
    BN_set_word(t0, 0);
    BN_set_word(t1, 1);
    
    BN_set_word(one,1);
    BN_hex2bn(&b12rsa->e,"65537");
    BN_hex2bn(&p,"C485F491D12EA7E6FEB95794E9FE0A819168AAC9D545C9E2AE0C561622F265FEB965754C875E049B19F3F945F2574D57FA6A2FC0A0B99A2328F107DD16ADA2A7");
    BN_hex2bn(&q,"F9A91C5F20FBBCCC4114FEBABFE9D6806A52AECDF5C9BAC9E72A07B0AE162B4540C62C52DF8A8181ABCC1A9E982DEB84DE500B27E902CD8FDED6B545C067CE4F");
    printf("p: ");
    BN_print_fp(stdout,p);
    printf("\n");
    printf("q: ");
    BN_print_fp(stdout,q);
    printf("\n");
    BIGNUM *gcd;

    BN_sub(p2,p,one);           //phin
    BN_sub(q2,q,one);
    BN_mul(tmp,p2,q2,ctx);
    BN_copy(phin,tmp);

    BN_mul(tmp,p,q,ctx);        //n
    BN_copy(b12rsa->n,tmp);
    
    BN_copy(a, b12rsa->e);
    BN_copy(b, phin);

    Xeuclid(a,b,x,y);
    BN_copy(b12rsa->d,x);
}



int main (int argc, char *argv[])
{
    BOB12_RSA *b12rsa = BOB12_RSA_new();
    BIGNUM *in = BN_new();
    BIGNUM *out = BN_new();

    if(argc == 2){
        if(strncmp(argv[1],"-k",2)){
            PrintUsage();
            return -1;
        }
        BOB12_RSA_KeyGen(b12rsa,1024);
        printf("n: ");
        BN_print_fp(stdout,b12rsa->n);
        printf("\n");
        printf("e: ");
        BN_print_fp(stdout,b12rsa->e);
        printf("\n");
        printf("d: ");
        BN_print_fp(stdout,b12rsa->d);
        printf("\n");
        
    }else if(argc == 5){
        if(strncmp(argv[1],"-e",2) && strncmp(argv[1],"-d",2)){
            PrintUsage();
            return -1;
        }
        BN_hex2bn(&b12rsa->n, argv[3]);
        BN_hex2bn(&in, argv[4]);
        if(!strncmp(argv[1],"-e",2)){
            BN_hex2bn(&b12rsa->e, argv[2]);
            BOB12_RSA_Enc(out,in, b12rsa);
        }else if(!strncmp(argv[1],"-d",2)){
            BN_hex2bn(&b12rsa->d, argv[2]);
            BOB12_RSA_Dec(out,in, b12rsa);
        }else{
            PrintUsage();
            return -1;
        }
        BN_print_fp(stdout,out);
        printf("\n");
    }else{
        PrintUsage();
        return -1;
    }

    if(in != NULL) BN_free(in);
    if(out != NULL) BN_free(out);
    if(b12rsa!= NULL) BOB12_RSA_free(b12rsa);
    
    
    return 0;
}