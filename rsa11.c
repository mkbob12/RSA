#include <stdio.h>
#include <openssl/bn.h>
#include <string.h>
#include <stdbool.h>
void printBN(char *msg, BIGNUM *a)
{
    char *number_str = BN_bn2dec(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}
//자체제작 함수------------------------------------------------------

//확장mod, a의e승(mod n)을 빠르게 구함
int ExpMod(BIGNUM *r, const BIGNUM *a, const BIGNUM *e, BIGNUM *m);

//확장유클리디안 함수, ax+by=c 에서 최대 공약수gcd(a,b)와 ax+by의 x,y를 구함
BIGNUM *XEuclid(BIGNUM *x, BIGNUM *y, const BIGNUM *a, const BIGNUM *b);

bool MillerRabin(BIGNUM *n)
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *a = BN_new();
    BIGNUM *zero = BN_new();
    BN_zero(zero);
    BIGNUM *one = BN_new();
    BN_one(one);
    BIGNUM *two = BN_new();
    BN_dec2bn(&two, "2");
    BIGNUM *N2 = BN_new();
    BN_sub(N2, n, one);
    BN_sub(N2, n, one); // n-2
    BIGNUM *N1 = BN_new();
    BN_sub(N1, n, one); // n-1
    BIGNUM *X = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *r = BN_new(); // r은 2^r*d=N-1
    BIGNUM *count = BN_new();
    BN_zero(count);
    BIGNUM *temp = BN_new();
    BN_copy(temp, N1);
    while (1)
    { // n1이 2로 나누어 떨어지면 진행
        // n1을 2로 나눈 나머지가 0일때
        // BN_mod(outsider,temp,two,ctx);//나머지 변수에 temp를 2로 나눈 나머지를 넣음
        // BN_is_odd(temp);
        if (!BN_is_odd(temp))
        {                                       //나머지가 0일때 -> 홀수가 아닐때
            BN_add(count, count, one);          // count++;
            BN_div(temp, NULL, temp, two, ctx); // temp에 temp를 2로 나눈 몫을 넣음
            BN_copy(r, count);
        }
        else
        { //더이상2로 나누어떨어지지않을때
            if (BN_cmp(count, zero) != 0)
            {
                BN_copy(d, temp);
                // printBN("out : ",d);
                break;
            }
        }
    }
    BIGNUM *r1 = BN_new();
    BN_sub(N1, n, one); // r-1
    BIGNUM *i = BN_new();
    BN_zero(i);

    for (int k = 0; k < 50; k++)
    {
        BN_rand_range(a, N2);
        ExpMod(X, a, d, n); // a^d (mod n)
        if (BN_cmp(X, one) == 0 || BN_cmp(X, N1) == 0)
        { // 0은 같을때
            continue;
        }
        for (; BN_cmp(r1, i) != 0; BN_add(i, i, one))
        {                         // i가 1씩증가, r-1이랑 같지 않을때만 돌아감
            ExpMod(X, X, two, n); // X=X^2 mod n
            if (BN_cmp(X, one) == 0)
            {
                return false;
            }
            if (BN_cmp(X, N1) == 0)
            { // n-1과 같을때
                break;
            }
        }
        if (BN_cmp(r1, i) == 0)
        {
            return false;
        }
    }
    return true;
    BN_free(a);
    BN_free(zero);
    BN_free(one);
    BN_free(two);
    BN_free(N2);
    BN_free(N1);
    BN_free(X);
    BN_free(d);
    BN_free(r);
    BN_free(count);
    BN_free(temp);
    BN_free(r1);
    BN_free(i);
    BN_CTX_free(ctx);
}

//----------------------------------------------------------------------

typedef struct _b11rsa_st
{
    BIGNUM *e;
    BIGNUM *d;
    BIGNUM *n;
} BOB11_RSA;

// RSA 구조체를 생성하여 포인터를 리턴하는 함수
BOB11_RSA *BOB11_RSA_new()
{
    BOB11_RSA *p = malloc(sizeof(BOB11_RSA)); // malloc
    p->e = BN_new();
    p->d = BN_new();
    p->n = BN_new();
    return p;
}

// RSA 구조체 포인터를 해제하는 함수
int BOB11_RSA_free(BOB11_RSA *b11rsa)
{
    BN_free(b11rsa->e);
    BN_free(b11rsa->d);
    BN_free(b11rsa->n);
}

// RSA 키 생성 함수
//입력 : nBits (RSA modulus bit size)
//출력 : b11rsa (구조체에 n, e, d 가  생성돼 있어야 함)
// p=C485F491D12EA7E6FEB95794E9FE0A819168AAC9D545C9E2AE0C561622F265FEB965754C875E049B19F3F945F2574D57FA6A2FC0A0B99A2328F107DD16ADA2A7
// q=F9A91C5F20FBBCCC4114FEBABFE9D6806A52AECDF5C9BAC9E72A07B0AE162B4540C62C52DF8A8181ABCC1A9E982DEB84DE500B27E902CD8FDED6B545C067CE4F
int BOB11_RSA_KeyGen(BOB11_RSA *b11rsa, int nBits)
{

    BN_CTX *ctx = BN_CTX_new();

    BIGNUM *p = BN_new();
    BN_rand(p, 512, 1, 1); // p,q를 홀수 랜덤 생성
    while (!MillerRabin(p))
    {
        BN_rand(p, 512, 1, 1);
    }

    BIGNUM *q = BN_new();
    BN_rand(q, 512, 1, 1);

    while (!MillerRabin(q))
    {
        BN_rand(q, 512, 1, 1);
    }

    BN_mul(b11rsa->n, p, q, ctx);

    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();

    BIGNUM *zero = BN_new();
    BN_zero(zero);
    BIGNUM *one = BN_new();
    BN_one(one);
    BIGNUM *p1 = BN_new();
    BN_sub(p1, p, one); //마이너스
    BIGNUM *q1 = BN_new();
    BN_sub(q1, q, one);

    BIGNUM *pn = BN_new();
    BN_mul(pn, p1, q1, ctx);      // pn=(q-1)(p-1)
    BN_rand_range(b11rsa->e, pn); // n보다 작은e를 랜덤생성

    while (!BN_is_one(XEuclid(x, y, pn, b11rsa->e))) // XEuclid가 1과 같으면 1
    {                                                // e랑n이 서로소가 아니라면 : BN_is_one이 1이 아니라면
        BN_rand_range(b11rsa->e, pn);                //다시 e를 랜덤
    }

    BN_one(b11rsa->d); //일단d는1
    BIGNUM *k = BN_new();
    BN_mul(k, b11rsa->e, b11rsa->d, ctx); // k=e*d
    BIGNUM *rem = BN_new();
    // x에 d y에 암거나, a에 e, b에 n
    XEuclid(b11rsa->d, k, b11rsa->e, pn);
    if (BN_cmp(b11rsa->d, zero) == -1)
    { // d가 음수면
        BN_add(b11rsa->d, b11rsa->d, pn);
    }

    BN_free(p);
    BN_free(q);
    BN_free(x);
    BN_free(y);
    BN_free(zero);
    BN_free(one);
    BN_free(p1);
    BN_free(q1);
    BN_free(pn);
    BN_free(k);
    BN_free(rem);
    BN_CTX_free(ctx);
}

// RSA 암호화 함수
//입력 : 공개키를 포함한 b11rsa, 메시지 m
//출력 : 암호문 c
int BOB11_RSA_Enc(BIGNUM *c, BIGNUM *m, BOB11_RSA *b11rsa)
{ // bob rsa:N
    ExpMod(c, m, b11rsa->e, b11rsa->n);
    return 1;
}

// RSA 복호화 함수
//입력 : 공개키를 포함한 b11rsa, 암호문 c
//출력 : 평문 m
int BOB11_RSA_Dec(BIGNUM *m, BIGNUM *c, BOB11_RSA *b11rsa)
{
    ExpMod(m, c, b11rsa->d, b11rsa->n);
    return 1;
}

/*
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!주의!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
1. 입출력은 모두 Hexadecimal 표현을 사용할 것!
2. Modular inversion과 modular exponentiation은 반드시 이전에 숙제로 작성했던 것을 사용할 것!
3. libcrypto의 함수는 가감승제와 비트연산, 입출력 함수 외에는 사용하지 말 것 (알아서 이 과정의 교육목표에 맞게 쓰시기 바랍니다).
*/
void PrintUsage()
{
    printf("usage: rsa [-k|-e e n plaintext|-d d n ciphertext]\n");
}

int main(int argc, char *argv[])
{
    BOB11_RSA *b11rsa = BOB11_RSA_new();
    BIGNUM *in = BN_new();
    BIGNUM *out = BN_new();

    if (argc == 2)
    {
        PrintUsage();
        if (strncmp(argv[1], "-e", 2))
        {
            PrintUsage();
            return -1;
        }
        BOB11_RSA_KeyGen(b11rsa, 1024);
        BN_print_fp(stdout, b11rsa->n);
        printf(" ");
        BN_print_fp(stdout, b11rsa->e);
        printf(" ");
        BN_print_fp(stdout, b11rsa->d);
    }
    else if (argc == 5)
    {
        if (strncmp(argv[1], "-e", 2) && strncmp(argv[1], "-d", 2))
        {
            PrintUsage();
            return -1;
        }
        BN_hex2bn(&b11rsa->n, argv[3]);
        BN_hex2bn(&in, argv[4]);
        if (!strncmp(argv[1], "-e", 2))
        {
            BN_hex2bn(&b11rsa->e, argv[2]);
            BOB11_RSA_Enc(out, in, b11rsa);
        }
        else if (!strncmp(argv[1], "-d", 2))
        {
            BN_hex2bn(&b11rsa->d, argv[2]);
            BOB11_RSA_Dec(out, in, b11rsa);
        }
        else
        {
            PrintUsage();
            return -1;
        }
        BN_print_fp(stdout, out);
    }
    else
    {
        PrintUsage();
        return -1;
    }

    if (in != NULL)
        BN_free(in);
    if (out != NULL)
        BN_free(out);
    if (b11rsa != NULL)
        BOB11_RSA_free(b11rsa);

    return 0;
}

int ExpMod(BIGNUM *r, const BIGNUM *a, const BIGNUM *e, BIGNUM *m)
{
    // a를e승 (mod m)한 결과
    BN_copy(r, a); //에 a의 값을 복사
    BN_CTX *ctx = BN_CTX_new();
    int i = BN_num_bits(e); // i는 e의 유효 비트수
    BIGNUM *p = BN_new();
    BN_dec2bn(&p, "2");
    for (i -= 2; i >= 0; i--)
    {
        BN_mod_exp(r, r, p, m, ctx);
        if (BN_is_bit_set(e, i) == 1)
        {
            BN_mod_mul(r, r, a, m, ctx);
        }
    }
}

BIGNUM *XEuclid(BIGNUM *x, BIGNUM *y, const BIGNUM *a, const BIGNUM *b) // x에 d y에 암거나, a에 e, b에 n
{
    BIGNUM *r1 = BN_new();
    BN_copy(r1, a);
    BIGNUM *r2 = BN_new();
    BN_copy(r2, b);
    BIGNUM *s1 = BN_new();
    BN_dec2bn(&s1, "1");
    BIGNUM *s2 = BN_new();
    BN_dec2bn(&s2, "0");
    BIGNUM *t1 = BN_new();
    BN_dec2bn(&t1, "0");
    BIGNUM *t2 = BN_new();
    BN_dec2bn(&t2, "1");
    BIGNUM *q = BN_new();
    BIGNUM *r = BN_new();
    BIGNUM *t = BN_new();
    BIGNUM *s = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *zero = BN_new();
    BN_zero(zero);
    BIGNUM *mul = BN_new();
    if (BN_cmp(a, b) != 1)
    {
        BN_swap(r1, r2);
    }
    while (BN_cmp(r2, zero) == 1)
    {                              // r2가 0보다 클때
        BN_div(q, r, r1, r2, ctx); // q=r1/r2, r=r1%r2;
        BN_copy(r1, r2);
        BN_copy(r2, r);

        BN_mul(mul, q, s2, ctx); // mul = q*s2
        BN_sub(s, s1, mul);      // s=s1-q*s2
        BN_copy(s1, s2);
        BN_copy(s2, s);

        BN_mul(mul, q, t2, ctx); // mul = q*t2
        BN_sub(t, t1, mul);      // t=t1-q*t2
        BN_copy(t1, t2);
        BN_copy(t2, t);
    }
    if (BN_cmp(a, b) != 1)
    {
        BN_copy(y, s1);
        BN_copy(x, t1);
    }
    else
    {
        BN_copy(x, s1);
        BN_copy(y, t1);
    }
    return r1;
}