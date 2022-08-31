One-time pad ,Caesar's cipher,Vigenere's cipher

FIRST NAME: NIKOLAOS
LAST NAME: MASTORAKIS



This assigment containes an implementation of three encryption algorythms One time pad,Caesars cipher and Vigenere cipher.When the runs the executable with the command ".\demoprogram" he can then input a plain text(only characters a-z,A-Z and 0-9 are allowed) for each algorythm and get the results of encryption and decryption.


All the requirements of this assignments where implemented and the output of the programm runs as it was supposed from the "Demo program" execution example.

The files that are required for this assigment are simple_crypto.c,simple_crypto.h and a MakeFile wich then can compile the library and create the executable ./demoprogram.

simple_crypto.h:
This is the file responsible for the functions declaration that are used in simple_crypto.c.

MakeFile:
This file contains commands responsible for simplifying and organizing the code compilation

simple_crypto.c:

This file contains the implementation of all the functions that are used in the programm and also the main function.The three functions OneTimePad,CaesarsCipher and VigenereCipher call the appropriate functions for each cipher to (1)get user input (2)filter the text and (3)execute the encryption of the plain text using the key (4)generated from /dev/urandom and then (5)decrypting the plaintext using the same key.The secret_key_creation()) function was used only on the OneTimePad() since the Caesars and Vigenere algorythms used the user input to create the encryption key functions.

Functions explanation:
char *  inputString(File *,size_t):This function is responsible to get user input of inifinite length until the user presses the ENTER.By using the realloc() I managed to save the user input in the heap which could be accessed using the char * str variable.

char * plaintext_filter(char *):This function is responsible to filter the user input and get rid of all special characters.More specifically the only characters that were allowed from the function to keep where numbers 0-9 ,lowercase a-z and uppercase A-Z.In this function the first for loop is used to check when we finished traversing the string.The while loop check if the character is not a character beetween a-z,A-Z and 0-9 and if it is not in this bounds then this character is not included at the final string that the function returns.

char * OTP_encrypt(char *,char *):This function gets as argument the plaintext after filtering from special characters and the secret key generated from the secret_key_creation() function and xors the characters of the plaintext and the key in order to create the cipher text.In order to get rid from non printable characters when printing the cipher at the end of the function the cipher non printable characters were converted to hexadecimal with the command sprintf() in a for loop.The for loop was used to convert each character seperately from its integer ASCII value to its hexadecimal format

char * OTP_decrypt(char *,char*):This function is used for the decryption of the cipher text.The only difference form the function OTP_decrypt is that there is no conversion from the integer value of non printable characters to hexadecimal because the decrypted text contains only printable characters from user input.

char * secret_key_creation(char *):This function reads one character at a time from the file of /dev/urandom and creates the final key for encryption and decryption.The argument is the plaintext because the key length must be equal or higher that the 
plaintexts length.

char * Caesars_encrypt(char *int):This function contains the code for the encryption of the plaintext given by the user using the Caesars cipher encryption algorythm.In this function we check with isalnum if the characters are alphanumeric and we shift.The reason for doing this is because at the ASCII table beetween 0-9 A-Z and a-z there are other characters wich should not be contained when shifting.For example if we want to shif character z by 1 then we should go to 0 and not to character '{'.The order of the characters when shifting is the following 
0-9,A-Z,a-z,0-9,A-Z,a-z,0-9,... .

char * Caesars_decrypt(char *, int ):This function contains the code for the decryption of the encrypted text which is generated in the Caesars encrypt function.This function is similar to Caesar_decrypt since the only difference is that the shift is backwards.

char * VignereCiphert_encrypt(char *int):This function contains the code for the encryption of the plaintext given by the user using the Vigenere cipher algorythm.

char * Caesars_decrypt(char *, int ):This function contains the code for the decryption of the Vigenere cipher text.


void OneTimePad(void):This function was used to run all the necessary functions to implement the logic of one time pad algorythm.(inputString(),plaintext_filter(),OTP_encrypt,OTP_decrypt(),secret_key_creation())

void CaesarsCipher(void):This function was used to run all the necessary functions to implement the logic of one time caesars cipher algorythm.(inputString(),plaintext_filter(),Caesars_encrypt(),Caesars_decrypt())

void VigenereCipher(void):This function was used to run all the necessary functions to implement the logic of Vigenere algorythm.(inputString(),VigenereCipher_encrypt(),VigenereCipher_decrypt())


gcc --version:
gcc (Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0



