#include "simple_crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>

//INFINITE USER INPUT FUNCTION----------------------------------------------
char *inputString(FILE* fp, size_t size){
    char *str;
    int ch;
    size_t len = 0;
    str = realloc(NULL, sizeof(*str)*size);//size is start size
    
    if(!str)
    {
    return str;
    
    }
    while(EOF!=(ch=fgetc(fp)) && ch != '\n'){
 
        str[len++]=ch;
        if(len==size){
            str = realloc(str, sizeof(*str)*(size+=16));
            if(!str)return str;
        }
    }
    str[len++]='\0';
    
    return realloc(str, sizeof(*str)*len);
}


//FILTER PLAINTEXT FUNCTION---------------------------------------------------------
char * plaintext_filter(char * str){
        int i,j;
         for (i = 0; str[i] != '\0'; ++i) {
     while (!(str[i] >= 'a' && str[i] <= 'z') && !(str[i] >= 'A' && str[i] <= 'Z') && !(str[i] >= '0' &&        str[i] <= '9') && !(str[i] == '\0')) {
         for (j = i; str[j] != '\0'; ++j) {
            str[j] = str[j + 1];
         }
         str[j] = '\0';
      }
   }
      
      

return str;
}


//OTP_ENCRYPTION FUNCTION----------------------------------------
char * OTP_encrypt(char * plain,char * secret_key){
        
char strStripped[strlen(plain)];//strStripped starting length is the length in bytes of the plaintext
char *  encrypted=(char*)malloc(strlen(plain));//dynamically allocate strlen(plain) bytes
secret_key[strlen(plain)]='\0';//add the escape character at the end


int j=0;
for(j = 0;j<strlen(plain);j++){//each character xor with the plaintext and key
char temp=(char)(plain[j] ^ secret_key[j]);
encrypted[j]=temp;
}
encrypted[strlen(plain)]='\0';


       
	 char *hex = (char*)malloc(strlen(encrypted));
	 for (int n = 0; n <strlen(encrypted); n++)
	  {
	    sprintf(&hex[n], "%02x", (unsigned int)encrypted[n]);
	  }
	  printf("%s",hex);
	   



return  encrypted;

}
//OTP DECRYPTION FUNCTION-----------------------------------------------
char * OTP_decrypt(char * cipher,char * secret_key){
char strStripped[strlen(cipher)];
char *  decrypted=(char*)malloc(strlen(cipher));


secret_key[strlen(cipher)]='\0';


int j=0;




for(j = 0;j<strlen(cipher);j++){//GET DECRYPTED
char temp=(char)(cipher[j] ^ secret_key[j]);
decrypted[j]=temp;
}
decrypted[strlen(cipher)]='\0';
        
	   
return  decrypted;

}
//SECRET KEY CREATION------------------------------------------------
char * secret_key_creation(char * plaintext)
{
//open dev/urandom file
FILE * fptr = fopen("/dev/urandom", "r");

//get all the file
char file=fgetc(fptr);

//key to encrypt and decrypt
char *key=(char*)malloc(strlen(plaintext));

//loop to create encr decr key
for(int i=0;i<strlen(plaintext);i++){

key[strlen(key)]=file;
file=fgetc(fptr);
}



fclose(fptr);
return key;
}
//ONE TIME PAD GENERAL FUNCTION-----------------------------------------------------------------
void OneTimePad(){


//GET USER INPUT
char  *plaintext_before;
char  *plaintext;

printf("[OTP] input: ");
plaintext_before=inputString(stdin, 10);//get user input
plaintext=plaintext_filter(plaintext_before);//filter from special characters


//SECRET KEY CREATION
char *secret_key=(char*)malloc(strlen(plaintext));
secret_key=secret_key_creation(plaintext);

//ENCRYPTION
char *encrypted_message=(char*)malloc(strlen(plaintext));
printf("[OTP] encrypted: ");
encrypted_message=OTP_encrypt(plaintext,secret_key);


//DECRYPTION
char *decrypted_message=(char*)malloc(strlen(encrypted_message));
decrypted_message=OTP_decrypt(encrypted_message,secret_key);
printf("\n[OTP] decrypted: %s",decrypted_message);
printf("\n");

//free from memory
free(secret_key);
free(plaintext);
free(encrypted_message);
free(decrypted_message);


}


//CAESARS ENCRYPTION FUNCTION-------------------------------------------
char * Caesars_encrypt(char * plaintext,int key){

int i = 0; 
char ch;

//for each charater
for(int j = 0 ; j < strlen(plaintext);j++)
{

	ch = plaintext[j];

while(i != key)//while i is not equal to key shifts
{
	
	if(isalnum(ch + 1))//check if character is number or a-z ,A-Z
	{

		
	i++;

	ch = ch + 1;//shift
	
    }
    else
    {
    	while(!isalnum(ch+1))//if not 0-9,a-z or A-Z just shift until a character 0-9a-zA-Z
    	{
    		ch = ch + 1;
    		
    	}
    }

    }

    i =0;
       plaintext[j] = ch;
      
	
}
  return plaintext;


}
//CAESARS DECRYPTION FUNCTION------------------------------------------
char * Caesars_decrypt(char * ciphertext,int key){

int i = 0; 
char ch;


for(int j = 0 ; j < strlen(ciphertext);j++)
{

	ch = ciphertext[j];

while(i != key)
{
	
	if(isalnum(ch - 1))
	{

		
	i++;

	ch = ch - 1;
	
    }
    else
    {
    	while(!isalnum(ch-1))
    	{
    		ch = ch - 1;
    	
    	}
    }

    }

    i =0;
       ciphertext[j] = ch;
      
	
}
  return ciphertext;


}
//CAESARS GENERAL FUNCTION------------------------------------------------
void CaesarsCipher(){

//GET USER INPUT
char  *plaintext_before;
char  *plaintext;
int secret_key;

printf("[Caesars] input: ");
fflush(stdin);

plaintext_before=inputString(stdin, 100);//user input
plaintext=plaintext_filter(plaintext_before);//filter plaintext from special characters



//GET KEY
printf("[Caesars] key: ");
scanf("%d",&secret_key);
getchar();

//ENCRYPTION DECRYPTION
char *encrypted_message=(char*)malloc(strlen(plaintext));
printf("[Caesars] encrypted: ");
encrypted_message=Caesars_encrypt(plaintext,secret_key);
printf("%s",encrypted_message);



//DECRYPTION
char *decrypted_message=(char*)malloc(strlen(encrypted_message));
printf("\n[Caesars] decrypted:");
decrypted_message=Caesars_decrypt(encrypted_message,secret_key );
printf("%s",decrypted_message);
printf("\n");


free(decrypted_message);//free from memory
}


//VIGENERE ENCRYPTION FUNCTION
char * VigenereCipher_encrypt(char * msg,char * key){

    int msgLen = strlen(msg);
    int keyLen = strlen(key);
    int i, j;
    char * newKey=(char*)malloc(msgLen);
    char * encryptedMsg=(char*)malloc(msgLen);

 
    //generating new key
    for(i = 0, j = 0; i < msgLen; ++i, ++j){
        if(j == keyLen)
            j = 0;
 
        newKey[i] = key[j];
    }
 
    newKey[i] = '\0';
 
    //encryption
    for(i = 0; i < msgLen; ++i)
        encryptedMsg[i] = ((msg[i] + newKey[i]) % 26) + 'A';
 
    encryptedMsg[i] = '\0';
    printf("%s\n",encryptedMsg);
    return encryptedMsg;
 
}

//VIGENERE DECRYPTION FUNCTION
char * VigenereCipher_decrypt(char * msg,char * key){

  
    int msgLen = strlen(msg);
    int keyLen = strlen(key);
    int i, j;
 
    char * newKey=(char*)malloc(msgLen);
    char * decryptedMsg=(char*)malloc(msgLen);
 
    //generating new key
    for(i = 0, j = 0; i < msgLen; ++i, ++j){
        if(j == keyLen)
            j = 0;
 
        newKey[i] = key[j];
    }
 
    newKey[i] = '\0';
 
    //decryption
    for(i = 0; i < msgLen; ++i)
        decryptedMsg[i] = (((msg[i] - newKey[i]) + 26) % 26) + 'A';
 
    decryptedMsg[i] = '\0';
 
  
    printf("%s\n",decryptedMsg);
return decryptedMsg;
}


//VIGENERE GENERAL FUNCTION
void VigenereCipher(){
//GET USER INPUT

char  *plaintext;


printf("[Vigenere] input :");
plaintext=inputString(stdin, 10);



char key_phrase[strlen(plaintext)];
printf("[Vigenere] key :");
scanf("%s",((char *)key_phrase));



char *encrypted_message=(char*)malloc(strlen(plaintext));
printf("[Vigenere] encrypted :");
encrypted_message=VigenereCipher_encrypt(plaintext,key_phrase);


char *decrypted_message=(char*)malloc(strlen(plaintext));
printf("[Vigenere] decrypted :");
decrypted_message=VigenereCipher_decrypt(encrypted_message,key_phrase);



}


//main function------------------------------------------------------------------------------------------------------------------
int main()
{

OneTimePad();
CaesarsCipher();
VigenereCipher();


return 0;
}
















