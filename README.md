# RSA
c++로 RSA 구현 및 ExpMod 구현 


# 명령어 
gcc exp_곽수찬.c -L.. -lcrypto  -I../include/crypto -o exp_곽수찬
./exp_곽수찬 123123123111 1293109238019381121


# 명령어 
gcc rsa.c -L.. -lcrypto  -I../include/crypto -o rsa
./rsa -k
./rsa [-k|-e e n plaintext|-d d n ciphertext]