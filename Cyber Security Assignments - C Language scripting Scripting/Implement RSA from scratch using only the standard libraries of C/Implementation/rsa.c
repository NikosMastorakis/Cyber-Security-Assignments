#include "rsa.h"
#include "utils.h"
#include "math.h"


/*
 * Sieve of Eratosthenes Algorithm
 * https://en.wikipedia.org/wiki/Sieve_of_Eratosthenes
 *
 * arg0: A limit
 * arg1: The size of the generated primes list. Empty argument used as ret val
 *
 * ret:  The prime numbers that are less or equal to the limit
 */
size_t *
sieve_of_eratosthenes(size_t* prime_final ,int limit, int *primes_sz)
{
	//size_t *primes;
	int n=limit;
	
	size_t prime[limit];
	//size_t prime[n+1];
	//Loading the array with numbers from 1 to n
	for(size_t i = 1; i <= n; i++)
	{
		prime[i] = i;
	}
	//Start with least prime number, which is 2.
	//No need to check for numbers greater than square root of n.
	//They will be already marked.
	
	for(size_t i = 2; i*i <= n; i++)
	{
		if(prime[i] != -1)
		{
			
			//Mark all the multiples of i as -1.
			for(size_t j = 2*i; j <=n ; j += i)
				prime[j] = -1;
		}
	}
	
	
	int k=0;
	for(int i=2; i <= limit; i++)
	{
	
		if(prime[i] != -1)
		{
		      
			
			  k++;
			
		
		}
	}
	
	
	int x= 0;
	
	for(int i=2; i <= limit; i++)
	{
	
		if(prime[i] != -1)
		{
		      
			prime_final[x]=i;
			
			  x++;
			
		
		}
	}
	

	return prime_final;
}


/*
 * Greatest Common Denominator
 *
 * arg0: first number
 * arg1: second number
 *
 * ret: the GCD
 */
int
gcd(int a, int b)
{
//for finding e

	int i, gcd;

	for(i = 1; i <= a && i <= b; ++i) {
		if(a % i == 0 && b % i == 0)
			gcd = i;
	}

	return gcd;

}


/*
 * Chooses 'e' where 
 *     1 < e < fi(n) AND gcd(e, fi(n)) == 1
 *
 * arg0: fi(n)
 *
 * ret: 'e'
 */
size_t
choose_e(size_t fi_n)
{
        size_t e = 1;
    while(1)
    {
        e=e+1;
        if((e%fi_n)!=0 && gcd(e,fi_n)==1)
        {
                break;
        }
     }

     
     return e;
}


/*
 * Calculates the modular inverse
 *
 * arg0: first number
 * arg1: second number
 *
 * ret: modular inverse
 */
size_t
mod_inverse(size_t e, size_t fi_n)

{
        
    int inv, u1, u3, v1, v3, t1, t3, q;
    int iter;
    /* Step X1. Initialise */
    u1 = 1;
    u3 = e;
    v1 = 0;
    v3 = fi_n;
    /* Remember odd/even iterations */
    iter = 1;
    /* Step X2. Loop while v3 != 0 */
    while (v3 != 0)
    {
        /* Step X3. Divide and "Subtract" */
        q = u3 / v3;
        t3 = u3 % v3;
        t1 = u1 + q * v1;
        /* Swap */
        u1 = v1; v1 = t1; u3 = v3; v3 = t3;
        iter = -iter;
    }
    /* Make sure u3 = gcd(u,v) == 1 */
    if (u3 != 1)
        return 0;   /* Error: No inverse exists */
    /* Ensure a positive result */
    if (iter < 0)
        inv = fi_n - u1;
    else
        inv = u1;
    return inv;

	
}


/*
 * Generates an RSA key pair and saves
 * each key in a different file
 */
void
rsa_keygen(void)
{
	size_t p=0;
	size_t q=0;
	size_t n;
	size_t fi_n;
	size_t e;
	size_t d;
	int n1,n2;
	
	
	size_t prime[RSA_SIEVE_LIMIT];
	size_t * primes = sieve_of_eratosthenes(prime,RSA_SIEVE_LIMIT , NULL);

	int size_of_primes = 0;
	int i = 0;
	//get size of primes
	while(primes[size_of_primes] >0)
	{

	size_of_primes++;

	}

	 srand((unsigned int)time(NULL));

	while(!p || n1<0 || n1> size_of_primes-1)
	{
	
	
       
	n1 = rand()%size_of_primes;
	p=primes[n1];//get first prime
	
	}

	while(!q  || (n2<0) || n2> size_of_primes -1)
	{
	n2 = rand()%size_of_primes;
	
	q=primes[n2];//get second prime
	
	}
	

	n = p * q;
	
	
	fi_n = (p - 1) * (q - 1);//calculate phin

	
	//choose e by gcd  ​(e % fi(n) != 0) AND (gcd(e, fi(n)) == 1)
	e = choose_e(fi_n);
	
	//choose d modularinverseof(e,fi(n)).​
	d=mod_inverse(e, fi_n);
	
	
	
	FILE *fOUT_pub;
	FILE *fOUT_priv;
	
   	fOUT_pub = fopen("public.key", "wb");
   	fwrite(&n, sizeof(size_t), 1, fOUT_pub);
   	fwrite(&e, sizeof(size_t),1, fOUT_pub);
   	
   	fclose(fOUT_pub);

   	fOUT_priv = fopen("private.key", "wb");
   	fwrite(&n, sizeof(size_t), 1, fOUT_priv);
   	fwrite(&d, sizeof(size_t),1, fOUT_priv);
   	
   
   
   	fclose(fOUT_priv);
   	
   	
	
	



}


/*
 * Encrypts an input file and dumps the ciphertext into an output file
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 */
int getFileSize(char * input_file)
{
/*get plaintext of input file*/
   FILE * fIN2;
   fIN2 = fopen(input_file, "r");
    /*Get file size*/
    fseek(fIN2, 0L, SEEK_END);
    int size_of_plaintext = ftell(fIN2);
    fclose(fIN2);
    return size_of_plaintext;

}
void
rsa_encrypt(char *input_file, char *output_file, char *key_file)
{

//get plaintext into 'buf'
  int size_of_plaintext=getFileSize(input_file);
  char * buf = (char *)malloc(size_of_plaintext);
  returnPlainText(buf,input_file);
  
 
  

//get key file into buf2
   size_t * buf2 = (size_t *)malloc(16);
   returnPlainText_key(buf2,key_file);
   size_t n = buf2[0];//n
   size_t e = buf2[1];//e

 
     size_t * buf3 = (size_t *)malloc(size_of_plaintext*sizeof(size_t));
 //get encrypted into buf3
 
     pow_mod( buf3, buf,e, n,size_of_plaintext);

        FILE *fOUT;
       
	
   	fOUT = fopen(output_file, "wb");
   	for(int i = 0; i< size_of_plaintext;i++)
   	{
   	fwrite(&buf3[i], sizeof(size_t), 1, fOUT);
   	}
   	
   	fclose(fOUT);




int size_of_ciphertext=getFileSize(output_file);





}


/*
 * Decrypts an input file and dumps the plaintext into an output file
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 */
void
rsa_decrypt(char *input_file, char *output_file, char *key_file)
{

//get ciphertext size
  int size_of_ciphertext=getFileSize(input_file);

  size_t * buf = (size_t *)malloc(size_of_ciphertext);
  
  
/*read every 8 bytes to buf[i]*/
  FILE * fIN;
  fIN = fopen(input_file, "rb");
  int k = 0;
  for(int i = 0; i< size_of_ciphertext/sizeof(size_t);i++)
  {
  fread(&buf[i],sizeof(size_t),1,fIN);
  k++;
  }
  fclose(fIN);
  
int size_of_plaintext_calculated = k;

      
/*get n and d of key_file to encrypt (size_t buffer) buf2*/
     size_t * buf2 = (size_t *)malloc(16);
     returnPlainText_key(buf2,key_file);

     
     size_t n = buf2[0];
     size_t d = buf2[1];
   
     
     char * buf3 = (char *)malloc(sizeof(char * )*size_of_plaintext_calculated);
     pow_mod_decr( buf3, buf,d, n,size_of_plaintext_calculated);
     
     char  plain[size_of_plaintext_calculated];
     for(int i = 0;i<size_of_plaintext_calculated;i++)
     {
     plain[i]=buf3[i];
     }
  
      
   	fIN = fopen(output_file, "wb");
   	
   	for(int i = 0; i< size_of_plaintext_calculated;i++)
   	{
   	
   
   	fwrite(&plain[i], 1,1, fIN);
   	
   	}
   	
   	fclose(fIN);




}



void returnPlainText(char * buf,char * input_file)
{
 FILE *f = fopen(input_file, "rb");
fseek(f, 0, SEEK_END);
long fsize = ftell(f);
fseek(f, 0, SEEK_SET);  /* same as rewind(f); */
fread(buf, fsize, 1, f);
fclose(f);
  
}
void returnPlainText_key(size_t * buf,char * input_file)
{
 FILE *f = fopen(input_file, "rb");
fseek(f, 0, SEEK_END);
long fsize = ftell(f);
fseek(f, 0, SEEK_SET);  /* same as rewind(f); */
fread(buf, fsize, 1, f);
fclose(f);
  
}

void  pow_mod(size_t * buf3,char * buf,size_t e,size_t n,int size_of_plaintext)
{


for(int i = 0; i<size_of_plaintext;i++)
{

size_t k = pow_mod_inside(buf[i],e,n);
buf3[i]=k;


}

}
void  pow_mod_decr(char * buf3,size_t * buf,size_t e,size_t n,int size_of_plaintext)
{


for(int i = 0; i<size_of_plaintext;i++)
{

char k = pow_mod_inside_decr(buf[i],e,n);
buf3[i]=k;


}

}
char pow_mod_inside_decr(size_t data, size_t e, size_t n) {

        size_t i;
        size_t result = 1;
        
        int base=data;
   
        for (i = 0; i < e; i++)
        {
                result = (result * base) % n;
        }
        
     char ch = result;
  return ch;

}



size_t pow_mod_inside(char data, size_t e, size_t n) {

        size_t i;
        size_t result = 1;
        
        int base=data;
   
        for (i = 0; i < e; i++)
        {
                result = (result * base) % n;
        }
      
     
  return result;

}






