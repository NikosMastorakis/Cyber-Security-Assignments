#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/des.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/cmac.h>

#define BLOCK_SIZE 16


/* function prototypes */
void print_hex(unsigned char *, size_t);
void print_string(unsigned char *, size_t); 
void usage(void);
void check_args(char *, char *, unsigned char *, int, int);
void keygen(unsigned char *, unsigned char *, unsigned char *, int);
unsigned char * encrypt(unsigned char*, char *,  char *, unsigned char *, 
    unsigned char *, int,int * );
unsigned char * decrypt( unsigned char * ,char *,  char *, unsigned char *, 
    unsigned char *, int ,int ,int *);
unsigned char * gen_cmac(unsigned char* ,unsigned char *,char *,char*,  unsigned char *, int,int);
int verify_cmac(unsigned char *, unsigned char *);
 unsigned char * returnPlainText(char * );
void before_verify_cmac(char *,char *,unsigned char* ,int);
long int findSize(char *);
/* TODO Declare your function prototypes here... */

long int findSize(char * file_name)
{
    // opening the file in read mode
    FILE* fp = fopen(file_name, "rb");
  
    // checking if the file exist or not
    if (fp == NULL) {
        printf("File Not Found!\n");
        return -1;
    }
  
    fseek(fp, 0L, SEEK_END);
  
    // calculating the size of the file
    long int res = ftell(fp);
  
    // closing the file
    fclose(fp);
  
    return res;
}

/*
 * Prints the hex value of the input
 * 16 values per line
 */
void
print_hex(unsigned char *data, size_t len)
{
	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++) {
			if (!(i % 16) && (i != 0))
				printf("\n");
			printf("%02X ", data[i]);
		}
		printf("\n");
	}
}


/*
 * Prints the input as string
 */
void
print_string(unsigned char *data, size_t len)
{
	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++)
			printf("%c", data[i]);
		printf("\n");
	}
}


/*
 * Prints the usage message
 * Describe the usage of the new arguments you introduce
 */
void
usage(void)
{
	printf(
	    "\n"
	    "Usage:\n"
	    "    assign_1 -i in_file -o out_file -p passwd -b bits" 
	        " [-d | -e | -s | -v]\n"
	    "    assign_1 -h\n"
	);
	printf(
	    "\n"
	    "Options:\n"
	    " -i    path    Path to input file\n"
	    " -o    path    Path to output file\n"
	    " -p    psswd   Password for key generation\n"
	    " -b    bits    Bit mode (128 or 256 only)\n"
	    " -d            Decrypt input and store results to output\n"
	    " -e            Encrypt input and store results to output\n"
	    " -s            Encrypt+sign input and store results to output\n"
	    " -v            Decrypt+verify input and store results to output\n"
	    " -h            This help message\n"
	);
	exit(EXIT_FAILURE);
}


/*
 * Checks the validity of the arguments
 * Check the new arguments you introduce
 */
void
check_args(char *input_file, char *output_file, unsigned char *password, 
    int bit_mode, int op_mode)
{
	if (!input_file) {
		printf("Error: No input file!\n");
		usage();
	}

	if (!output_file) {
		printf("Error: No output file!\n");
		usage();
	}

	if (!password) {
		printf("Error: No user key!\n");
		usage();
	}

	if ((bit_mode != 128) && (bit_mode != 256)) {
		printf("Error: Bit Mode <%d> is invalid!\n", bit_mode);
		usage();
	}

	if (op_mode == -1) {
		printf("Error: No mode\n");
		usage();
	}
}

//This function is responsible for returning the plain text 
 unsigned char * returnPlainText(char * input_file){  
               FILE *fp;
		long lSize;
		unsigned  char *buffer;

		fp = fopen ( input_file , "rb" );
		if( !fp ) perror(input_file),exit(1);

		fseek( fp , 0L , SEEK_END);
		lSize = ftell( fp );
		rewind( fp );

		buffer = calloc( 1, lSize+1 );
		if( !buffer ) fclose(fp),fputs("memory alloc fails",stderr),exit(1);

		if( 1!=fread( buffer , lSize, 1 , fp) )
		  fclose(fp),free(buffer),fputs("entire read fails",stderr),exit(1);
		
		fclose(fp);
	
	
		return buffer;
}

/*
 * Generates a key using a password
 */
void
keygen(unsigned char *password, unsigned char *key, unsigned char *iv,
    int bit_mode)
{ 

	if(bit_mode==128)
		{
	
        int i =  EVP_BytesToKey(EVP_aes_128_ecb(),
          EVP_sha1(), NULL,
          password,
          strlen((const char *)password),
          1, 
          key,
          iv);
         
	
	if (i != 16) {
			printf("Key size is %d bits - should be 128 bits\n", i);
    		
  		      }
  		}
  	if(bit_mode==256)
		{
		
	
        int i =  EVP_BytesToKey(EVP_aes_256_ecb(), EVP_sha1(), NULL, password,
         strlen((const char *)password), 1, key, iv);
	
	if (i != 32) {
			printf("Key size is %d bits - should be 128 bits\n", i);
    	
  		      }
  		}
}


unsigned char *
encrypt(unsigned char * plaintext_,char *input_file,char * output_file, unsigned char *key,
    unsigned char *iv, int bit_mode,int   * length)
{
 unsigned  char * plaintext ;
 if(input_file!=NULL)
 {
  plaintext = returnPlainText(input_file);
  }
  else
  {
  plaintext=plaintext_;
  
  }
  plaintext[strlen((char *)plaintext)]='\0';

  int plaintext_len=strlen((char*)plaintext)+1;//get plaintext length
  
  int  c_len=0;
  int f_len=0;

  EVP_CIPHER_CTX *e_ctx;//icnit evp ctx
  e_ctx=EVP_CIPHER_CTX_new();
   unsigned char * ciphertext = (unsigned char*)malloc(plaintext_len+BLOCK_SIZE-1);//cipher size
  
  
   if(bit_mode==128)		//check for bit_mode
 	EVP_EncryptInit_ex(e_ctx, EVP_aes_128_ecb(), NULL, key, iv);
 	
  if(bit_mode==256)
	EVP_EncryptInit_ex(e_ctx,EVP_aes_256_ecb(), NULL, key, iv);
	
  EVP_EncryptUpdate(e_ctx, ciphertext, &c_len, plaintext, plaintext_len);//update ctx without last block if thers padding
  EVP_EncryptFinal_ex(e_ctx, ciphertext+c_len, &f_len);//padd ctx
   unsigned char *cipher_text = (unsigned char * ) malloc(c_len+f_len); 
   memcpy(cipher_text, ciphertext, c_len+f_len);
  
  if(output_file!=NULL)
{
   FILE *fOUT;
   fOUT = fopen(output_file, "wb");
   fwrite(cipher_text, sizeof(unsigned char),c_len+f_len, fOUT);
   fclose(fOUT);
 }

//get the length of the cipher outside of the function
 *length=c_len+f_len; 
EVP_CIPHER_CTX_cleanup(e_ctx);

   return cipher_text;

}



unsigned char *
decrypt(unsigned char * cipher,char *input_file,char * output_file, unsigned char *key,
    unsigned char *iv, int bit_mode,int  ciphertext_len,int  * decr_length)
{
unsigned  char * ciphertext ;
 if(input_file!=NULL)//check if we need to open a file to get plaintext
 {
  	ciphertext = returnPlainText(input_file);
  	 ciphertext_len = findSize(input_file);
  	
  	}
  	
if(input_file==NULL)//or if functions input is the plaintext
{
  	ciphertext=cipher;
  	
  	}


 
   
   int f_len=0;
   int  p_len;
   unsigned char * plaintext = (unsigned char*)malloc(ciphertext_len);//malloc plaintext
  
   EVP_CIPHER_CTX *e_ctx;//declare e_ctx
   e_ctx=EVP_CIPHER_CTX_new();
   
   if(bit_mode==128)	//init e_ctx
 	EVP_DecryptInit_ex(e_ctx,EVP_aes_128_ecb(), NULL, key, iv);
 	
  if(bit_mode==256)
	EVP_DecryptInit_ex(e_ctx,EVP_aes_256_ecb(), NULL, key, iv);
	
  EVP_DecryptUpdate(e_ctx, plaintext, &p_len, ciphertext, ciphertext_len);//update e_ctx
   
  EVP_DecryptFinal_ex(e_ctx, plaintext+p_len, &f_len);//add padding to e_ctx
 
  int plaintext_len =p_len+f_len;//get new plain length
  unsigned char *plain_text = malloc(plaintext_len);
 
   *decr_length=plaintext_len;
   memcpy((unsigned char *)plain_text, plaintext, plaintext_len);//copy to plaintext
  if(input_file!=NULL)
     {
	  FILE *fOUT;
	  fOUT = fopen(output_file, "wb");
	   fwrite(plain_text, sizeof(unsigned char),plaintext_len, fOUT);//write to fule
	 
	   fclose(fOUT);
     }

  EVP_CIPHER_CTX_cleanup(e_ctx);
  return plaintext;
 	
}


unsigned char *
gen_cmac(unsigned char * tag,unsigned char * plaintext_,char *input_file,char* output_file,  unsigned char *key, int bit_mode,int plaintext_len)
{
        
        
	unsigned char * plaintext;
	if(input_file!=NULL)//check if input is file name and update plaintext_len
	{
             plaintext = returnPlainText(input_file);
             plaintext_len=findSize(input_file);//function that gets file size
                 
        }    
        if(input_file==NULL)//plain text is input at the function
             plaintext=plaintext_;

	/* Create a new CMAC context */
	CMAC_CTX *cmac_new = CMAC_CTX_new();
	if(bit_mode==128){
 		CMAC_Init(cmac_new, key, 16,EVP_aes_128_ecb(), NULL);
  	}
  	if(bit_mode==256){
		CMAC_Init(cmac_new, key, 32,EVP_aes_256_ecb(), NULL);
  	}
        CMAC_Update(cmac_new, plaintext, plaintext_len);
        size_t tag_size;
        CMAC_Final(cmac_new, tag, &tag_size);
        CMAC_CTX_free(cmac_new);
        
        int  lenCipher;//holds the size of cipher of the plain text to encrypt
          
          if(output_file!= NULL)//write cipher and cmac to output file
          {
                 unsigned char * cipher = encrypt(plaintext,NULL,output_file, key,NULL,bit_mode,&lenCipher);
    
                  FILE *fOUT;
                  fOUT = fopen(output_file, "wb");
                  fwrite(cipher, sizeof(unsigned char),lenCipher, fOUT);
             	  fclose(fOUT);
             
                  fOUT = fopen(output_file, "a");
                  fwrite(tag, sizeof(unsigned char),BLOCK_SIZE, fOUT);
             	  fclose(fOUT);
             	    unsigned char * cipher_cmac = (unsigned char * )malloc(lenCipher+BLOCK_SIZE);
                  int total=0;
                  
                //concatenate cipher and mac to a common buffer
                for(int k = 0; k<lenCipher;k++)
                {
                        cipher_cmac[total]=cipher[k];
                        total++;
                        
                }
                for(int k = lenCipher; k<lenCipher+BLOCK_SIZE;k++)
                {
                        cipher_cmac[total]=tag[k];
                        total++;
                        
                }
          
   	
   	
     	  }
          
           return tag;
}


//function to verify mac
int
verify_cmac(unsigned char *cmac1, unsigned char *cmac2)
{  
   int verify;  
   if(strcmp((char *)cmac1,(char *)cmac2)==0)  
   {
           verify=0;
           
   }
   else{
           verify=1;
   }

	return verify;
}

void before_verify_cmac(char * input_file,char * output_file, unsigned char *key,int bit_mode)
{
unsigned char * encrypted = returnPlainText((char *)input_file);//concatenated encrypted text

long int encrypted_len = findSize(input_file);//position of encrypted first byte
int pos=encrypted_len-BLOCK_SIZE;//position of cmacs first byte

unsigned char * buf=(unsigned char * )malloc(pos);//store ciphertext
unsigned char * tag=(unsigned char * )malloc(BLOCK_SIZE);//store cmac

memcpy(buf,encrypted,pos);//get ciphertext
memcpy(tag,&encrypted[pos],BLOCK_SIZE);//store cmac

int  plain_len;
unsigned char * plaintext = decrypt(buf,NULL,NULL, key,NULL,bit_mode,pos,&plain_len);//decrypt the 




//CREATE MAC FOR CIPHER 
unsigned char tag2[BLOCK_SIZE];

gen_cmac(tag2, plaintext,NULL,NULL,key,bit_mode,plain_len);

/*call verify function wich returns TRUE or FALSE if cmacs are same or not*/
int verify = verify_cmac(tag,tag2);

if(verify==0)
{

 FILE *fOUT;
 fOUT = fopen(output_file, "wb");
 fwrite(plaintext, sizeof(unsigned char),strlen((char*)plaintext)+1, fOUT);
 fclose(fOUT);  
 printf("\nCMAC VERIFIED");   
}

else{
        
printf("\nCMAC NOT VERIFIED");
}



}


int
main(int argc, char **argv)
{
	int opt;			/* used for command line arguments */
	int bit_mode;			/* defines the key-size 128 or 256 */
	int op_mode;			/* operation mode */
	char *input_file;		/* path to the input file */
	char *output_file;		/* path to the output file */
	unsigned char *password;	/* the user defined password */

	/* Init arguments */
	input_file = NULL;
	output_file = NULL;
	password = NULL;
	bit_mode = -1;
	op_mode = -1;


	/*
	 * Get arguments
	 */

	while ((opt = getopt(argc, argv, "b:i:m:o:p:desvh:")) != -1) {
		switch (opt) {
		case 'b':
		//make string to integer
			bit_mode = atoi(optarg);

			break;
		case 'i':
			input_file = strdup(optarg);
			break;
		case 'o':
			output_file = strdup(optarg);
			break;
		case 'p':
			password = (unsigned char *)strdup(optarg);
			break;
		case 'd':
			/* if op_mode == 1 the tool decrypts */
			op_mode = 1;
			break;
		case 'e':
			/* if op_mode == 0 the tool encrypts */
			op_mode = 0;
			break;
		case 's':
			/* if op_mode == 1 the tool signs */
			op_mode = 2;
			break;
		case 'v':
			/* if op_mode == 1 the tool verifies */
			op_mode = 3;
			break;
		case 'h':
		default:
			usage();
		}
	
		
		

	}
	
	/*create key */
	 	unsigned char * key  = (unsigned char * )malloc(bit_mode);
	 	keygen(password,key, NULL,bit_mode);
	 	
	 	
		if(op_mode==0){//Encryption
                int len=0;
    		encrypt(NULL,input_file,output_file, key,NULL,bit_mode,&len);
    		
    		}
    		if(op_mode==1){//Decryption
    	        int decr_length=0;
    		decrypt(NULL,input_file,output_file, key,NULL,bit_mode,decr_length,&decr_length);
    		
    		}
    		if(op_mode==2){
  
    		unsigned char tag[BLOCK_SIZE];
    		gen_cmac(tag,NULL,input_file,output_file,key,bit_mode,0);
    			
    		//ma
   
    		}
    		if(op_mode==3)
    		{
    		before_verify_cmac(input_file,output_file,key,bit_mode);
    		
    		}
    		
	check_args(input_file, output_file, password, bit_mode, op_mode);
	
	
	free(input_file);
	free(output_file);
	free(password);


	/* END d*/
	return 0;
}
