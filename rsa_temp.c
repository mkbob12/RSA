
#include <stdio.h>
#include <openssl/bn.h>
#include <string.h>
#include <stdlib.h>



typedef struct _b12rsa_st {
    BIGNUM *e;
    BIGNUM *d;
    BIGNUM *n;
}BOB12_RSA;


int BOB12_RSA_free(BOB12_RSA *b12rsa);
int BOB12_RSA_KeyGen(BOB12_RSA *b12rsa, int nBits);
int BOB12_RSA_Enc(BIGNUM *c, BIGNUM *m, BOB12_RSA *b12rsa);
int BOB12_RSA_Dec(BIGNUM *m,BIGNUM *c, BOB12_RSA *b12rsa);
void PrintUsage();
BOB12_RSA *BOB12_RSA_new();
BIGNUM *XEuclid(BIGNUM *x, BIGNUM *y, const BIGNUM *a, const BIGNUM *b);


// 자체 제작
int ExpMod(BIGNUM *r, const BIGNUM *a, const BIGNUM *e, BIGNUM *m);
void printBN(char *msg, BIGNUM * a);



int main (int argc, char *argv[])
{
    BOB12_RSA *b12rsa = BOB12_RSA_new();
    BIGNUM *in = BN_new();
    BIGNUM *out = BN_new();

    printf("hello");
 

    if(argc == 2){
        if(strncmp(argv[1],"-k",2)){
            PrintUsage();
            return -1;
        }
        
        BOB12_RSA_KeyGen(b12rsa,1024);
        BN_print_fp(stdout,b12rsa->n);
        printf(" ");
        BN_print_fp(stdout,b12rsa->e);
        printf(" ");
        BN_print_fp(stdout,b12rsa->d);
        printf(" v");
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
    }else{
        PrintUsage();
        return -1;
    }

    if(in != NULL) BN_free(in);
    if(out != NULL) BN_free(out);
    if(b12rsa!= NULL) BOB12_RSA_free(b12rsa);

    return 0;
};

// 구조체 생성 
BOB12_RSA *BOB12_RSA_new()
{
    BOB12_RSA *rsa = (BOB12_RSA *)malloc(sizeof(BOB12_RSA));
    rsa->e = BN_new();
    rsa->d = BN_new();
    rsa->e = BN_new();
   
    return rsa;
};

void PrintUsage()
{
    printf("usage: rsa [-k|-e e n plaintext|-d d n ciphertext]\n");
}

int BOB12_RSA_free(BOB12_RSA *b12rsa) {
    BN_free(b12rsa->e);
    BN_free(b12rsa->d);
    BN_free(b12rsa->n);
    return -1;
};


BIGNUM *XEuclid(BIGNUM *x, BIGNUM *y, const BIGNUM *a, const BIGNUM *b)
{
    // 

    BIGNUM *r1, *r2, *s1, *s2, *t1, *t2, *q, *r, *s, *t, *c;
    BIGNUM *gcd = BN_new();
    
    // ====== 초기값 설정 ======== 
    r1 = BN_dup(a); // copy a to r1
    r2 = BN_dup(b); // copy b to r2 

    s1 = BN_new();
    s2 = BN_new();
    t1 = BN_new();
    t2 = BN_new();
    

    q = BN_new();
    r = BN_new();
    s = BN_new();
    t = BN_new();
    c = BN_new(); // 변수 c 초기화


    BN_set_word(s1,1);
    BN_set_word(s2,0);
    BN_set_word(t1,0);
    BN_set_word(t2,1);
    
    while(BN_is_zero(r2) != 1){
        // 임시 buff 
        
        
        BN_div(q, r, r1, r2, BN_CTX_new()); // q = r1 /r2 , r = r1 % r2 
        r1 = BN_dup(r2);
        r2 = BN_dup(r);
   
        //BN_mul(r, q, s2, BN_CTX_new());

        // s = s1 - s2 * q 
        BN_mul(c, q, s2, BN_CTX_new()); // c = s2 * q 
        BN_sub(c,s1,c); // s1 - s2 * q  
    
        s = BN_dup(c);
        
        // dump 하기 
        s1 = BN_dup(s2);
        s2 =  BN_dup(s);

        // t = t1 - t2 * q 
        BN_mul(c,q,t2 ,BN_CTX_new()); // c = t2 * q 
        BN_sub(c,t1,c); // t1 - t2 * q
        t = BN_dup(c); // t = t1 - t2  * q  
        t1 = BN_dup(t2);
        t2 = BN_dup(t);

      
    }
    gcd = BN_dup(r1);
    BN_copy(x, s1); // BN_dup 가 아닌 BN_copy로 해야 오류 해결  ) 이유는 ,, 
    BN_copy(y, t1);

 
    // 할당 해제 
    BN_free(q);
    BN_free(r1);
    BN_free(r2);
    BN_free(r);
    BN_free(s1);
    BN_free(s2);
    BN_free(s);
    BN_free(t1);
    BN_free(t2);
    BN_free(t);
    BN_free(c);

    

    return gcd;
    
}

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
	/* Use BN_bn2hex(a) for hex string * Use BN_bn2dec(a) for decimal string */ 
	char * number_str = BN_bn2hex(a);
	printf("%s %s\n", msg, number_str); 
	OPENSSL_free(number_str); 
};


int BOB12_RSA_KeyGen(BOB12_RSA *b12rsa, int nBits){
    printf("hello");

    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *ph = BN_new();
    BIGNUM *zero = BN_new();
    BIGNUM *gcd = BN_new();
    BIGNUM *e = BN_new();
    BN_zero(zero);

    const char *p ="C485F491D12EA7E6FEB95794E9FE0A819168AAC9D545C9E2AE0C561622F265FEB965754C875E049B19F3F945F2574D57FA6A2FC0A0B99A2328F107DD16ADA2A7";
    const char *q = "F9A91C5F20FBBCCC4114FEBABFE9D6806A52AECDF5C9BAC9E72A07B0AE162B4540C62C52DF8A8181ABCC1A9E982DEB84DE500B27E902CD8FDED6B545C067CE4F";
   
    // n = p * q 
    BN_mul(b12rsa->n, p, q, NULL);

   
    BN_sub(p, p, BN_value_one());
    BN_sub(q, q, BN_value_one());

    BN_mul(ph, p, q, ctx);
    BN_dec2bn(&e, "65537");
\
    BN_gcd(gcd, e, ph, ctx); // r = a % b

    while(!BN_is_one(gcd)){
        BN_add(e,e, BN_value_one());
        BN_gcd(gcd,e, ph,ctx);
    }

    BN_copy(b12rsa->e, e);
    XEuclid(b12rsa->d, NULL, b12rsa->e, ph);

    if(BN_cmp(b12rsa->d, zero) == -1){
        BN_add(b12rsa->d, b12rsa->d, ph);
    }
    

   
    BN_free(p);
    BN_free(q);
    BN_free(ph);
    BN_free(zero);
    BN_free(gcd);
    BN_CTX_free(ctx);

    return 0;

};

int BOB12_RSA_Enc(BIGNUM *c, BIGNUM *m, BOB12_RSA *b12rsa){

    ExpMod(c, m, b12rsa->e, b12rsa->n);

    return 1;
};


int BOB12_RSA_Dec(BIGNUM *m,BIGNUM *c, BOB12_RSA *b12rsa){

    ExpMod(m,c, b12rsa->d, b12rsa->n);

    return 1;
}

