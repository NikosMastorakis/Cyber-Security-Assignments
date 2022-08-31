#include <stdio.h>
#ifndef SIMPLE_CRYPTO_H    /* This is an "include guard" */
#define SIMPLE_CRYPTO_H


char * inputString(FILE * , size_t ); //get user input(infinite size)
char * plaintext_filter(char *);       //filter all characters except [A-Z,a-z] and 0-9
char * OTP_encrypt(char * ,char * );//encrypt or decrypt function(OTP)
char * OTP_encrypt(char * ,char * );
char * secret_key_creation(char *);
void OneTimePad(void);

char * Caesars_encrypt(char * ,int );
char * Caesars_decrypt(char *,int );
void CaesarsCipher(void);


char * VigenereCipher_encrypt(char * ,char *);
char * VigenereCipher_decrypt(char * ,char * );
void VigenereCipher(void);
#endif
