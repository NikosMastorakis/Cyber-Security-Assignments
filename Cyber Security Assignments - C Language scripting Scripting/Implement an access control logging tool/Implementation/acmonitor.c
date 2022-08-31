#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


struct entry {

	int uid; /* user id (positive integer) */
	int access_type; /* access type values [0-2] */
	int action_denied; /* is action denied values [0-1] */

	char *  date; /* file access date */
	char *  time; /* file access time */

	char *file; /* filename (string) */
	char *fingerprint; /* file fingerprint */

	/* add here other fields if necessary */
	/* ... */
	/* ... */

};
struct entry_fing {

	int uid; /* user id (positive integer) */
	char *file; /* filename (string) */
	char *fingerprint; /* file fingerprint */

	/* add here other fields if necessary */
	/* ... */
	/* ... */

};

struct entry_fing2 {

	
	char *fingerprint; /* file fingerprint */

	/* add here other fields if necessary */
	/* ... */
	/* ... */

};
struct entry_file {

	
	char *file; /* filename (string) */
	

	/* add here otherr fields if necessary */
	/* ... */
	/* ... */

};






int getLineNumber(char * line_array,int log_size,FILE * file)//get number of lines in file
     {
     int line_number;
      while (fgets(line_array, log_size, file)) {
      line_number ++ ;
      }
      return line_number;
     }


void
usage(void)
{
	printf(
	       "\n"
	       "usage:\n"
	       "\t./monitor \n"
		   "Options:\n"
		   "-m, Prints malicious users\n"
		   "-i <filename>, Prints table of users that modified "
		   "the file <filename> and the number of modifications\n"
		   "-h, Help message\n\n"
		   );

	exit(1);
}
char * returnPlainText(char * buf)//return file plaintext
{
    size_t k = 0;//get file size
    FILE * fIN2;
    fIN2 = fopen("/var/tmp/file_logging.log", "r");
    fseek(fIN2, 0L, SEEK_END);
    int sz = ftell(fIN2);
    fclose(fIN2);

    FILE * fIN;//Get loggin plain text into buf1
    fIN = fopen("/var/tmp/file_logging.log", "r");
    char * buf1 = (char * )malloc(sz);
    if (fIN == NULL)
    {
        printf("File is not available \n");
    }
    else
    {
   
    char ch;
    while ((ch = fgetc(fIN)) != EOF)
        {
            
             buf1[k]=ch;
          
             k++;
             
        if(k==sz)
        {
	  break;
        }
       }
       
       
    }
     fclose(fIN);
return buf1;

}
int getFileSize(char * input_file)//get file size function
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
list_unauthorized_accesses(FILE *log)
{

   int log_size=getFileSize("/var/tmp/file_logging.log");//log file size
   char * log_text = (char * )malloc(log_size);

   log_text=  returnPlainText(log_text);//log file plain text
   
   FILE* file = fopen("/var/tmp/file_logging.log", "r"); 

   int line_number = 0;
   int size_of_line=0;
   char * log_entry = (char * )malloc(21);
   char * line_array = (char * )malloc(log_size);
   line_number=getLineNumber(line_array,log_size,file);//get line number

     
   struct entry arr_entry[line_number];//fill struct with logs
    
   FILE* file2 = fopen("/var/tmp/file_logging.log", "r");
   char * line_array2 = (char * )malloc(log_size);//fill array with logs(size is full file size)

  
   int lines=0;
    while (fgets(line_array2, log_size, file2)) {

	size_of_line=strlen(line_array2);//get size of line

	if(strncmp(line_array2,"UID:",strlen("UID:"))==0)//uid----------------------------
	{
	  for(int i = 0 ;i < 3;i++)
		{
		log_entry[i]=line_array2[i];
		}
	int strct_uid = 0;
	int first_char=strlen("UID:");//log entry type
	int last_char = strlen(line_array2);//full log entry
	char arr_uid[last_char-first_char];//content of log entry
	int k = 0;
	for(int i =first_char;i<=last_char;i++)
	{
	arr_uid[k]=line_array2[i];//copy the the content of log entry
	k++;
	}

	arr_entry[lines].uid=atoi(arr_uid);//insert it to array

	fgets(line_array2, log_size, file2);//get next line
	}
	
	if(strncmp(line_array2,"File name:",strlen("File name:"))==0)//filename---------------
	{
		for(int i = 0 ;i < 9;i++)
		{
		log_entry[i]=line_array2[i];
		}

	int strct_filename = 0;
	int first_char=strlen("File name:");
	int last_char = strlen(line_array2);
	char arr_filename[last_char-first_char];
	
	int k = 0;
	for(int i =first_char;i<=last_char;i++)
	{
	arr_filename[k]=line_array2[i];
	
	k++;
	
	}
	arr_entry[lines].file=(char * )malloc(k);
	strcpy(arr_entry[lines].file,arr_filename);
	fgets(line_array2, log_size, file2);

	}
	if( strncmp(line_array2,"Date:",strlen("Date")+1)==0)//date---------------------------------
	{

		for(int i = 0 ;i < 4;i++)
		{
		log_entry[i]=line_array2[i];
		}
	
	

	int strct_date = 0;
	int first_char=strlen("Date:");
	int last_char = strlen(line_array2);
	char arr_date[last_char-first_char];
	
	int k = 0;
	for(int i =first_char;i<=last_char;i++)
	{
	arr_date[k]=line_array2[i];
	
	k++;
	}
	
	
	arr_entry[lines].date=(char * )malloc(k);
	strcpy((char * )arr_entry[lines].date,(const char * )arr_date);
	//printf("\n Date of strct = %s\n",arr_entry[lines].date);
	fgets(line_array2, log_size, file2);
	//printf("\n(DATE)arr_entry[%d]=%s",lines,arr_entry[lines].date);

	}
	
	
	
	
	if(strncmp(line_array2,"Timestamp:",strlen("Timestamp:"))==0)//timestamp---------------------
	{
		
		for(int i = 0 ;i < 9;i++)
		{
		log_entry[i]=line_array2[i];
		}
	
	
	//set Date
	//printf("\nIS Timestamp");
	int strct_timestamp = 0;
	int first_char=strlen("Timestamp:");
	int last_char = strlen(line_array2);
	char arr_timestamp[last_char-first_char+1];
	
	int k = 0;
	for(int i =first_char;i<=last_char;i++)
	{
	arr_timestamp[k]=line_array2[i];
	
	k++;
	}
	
	arr_entry[lines].time=(char * )malloc(k);
	strcpy((char *)arr_entry[lines].time,(const char * )arr_timestamp);
	


	fgets(line_array2, log_size, file2);

	}

	if(strncmp(line_array2,"Access Type:",strlen("Access Type:"))==0)//access type-----------------------
	{

		for(int i = 0 ;i < 11;i++)
		{
		log_entry[i]=line_array2[i];
		}
	
	
	int strct_access_type = 0;
	int first_char=strlen("Access Type:");
	int last_char = strlen(line_array2);
	char arr_access_type[last_char-first_char+1];
	
	int k = 0;
	for(int i =first_char;i<=last_char;i++)
	{
	arr_access_type[k]=line_array2[i];
	
	k++;
	}
	
	
	arr_entry[lines].access_type=atoi(arr_access_type);
	fgets(line_array2, log_size, file2);


	

	}
	
	if(strncmp(line_array2,"Is-action-denied flag:",strlen("Is-action-denied flag:"))==0){//actiondenied
	
		
		for(int i = 0 ;i < 21;i++)
		{
		log_entry[i]=line_array2[i];
		}
	
	

	int strct_action_denied = 0;
	int first_char=strlen("Is-action-denied flag:");
	int last_char = strlen(line_array2)-1;
	char arr_action_denied [last_char-first_char];
	for(int i = 0; i < strlen(line_array2);i++)
	{

	
	}
	
	int k = 0;
	for(int i =first_char;i<=last_char;i++)
	{
	arr_action_denied [k]=line_array2[i];
	k++;
	}
	
	
	arr_entry[lines].action_denied=atoi(arr_action_denied );
	fgets(line_array2, log_size, file2);

	
	

	
	}
	if(strncmp(line_array2,"File fingerprint:",strlen("File fingerprint:"))==0) //file fingerprint-----
	             {
	         for(int i = 0 ;i < 18;i++)
		{
		log_entry[i]=line_array2[i];
		}
	
	//set fingerprint
	//printf("\nIS FINGERPRINT");
	int strct_fingerprint = 0;
	int first_char=strlen("File fingerprint:");
	int last_char = strlen(line_array2);
	char arr_fingerprint[last_char-first_char];
	int k = 0;


	for(int i =first_char;i<=last_char;i++)
	{


	arr_fingerprint[k]=line_array2[i];
	
	k++;
	}
	arr_entry[lines].fingerprint=(char * )malloc(k);
	strcpy(arr_entry[lines].fingerprint,arr_fingerprint);
	
	}

	
lines++;//get total number of seperate log entries of struct
	
    }
       

   int array_of_uid;
   int num_of_logs=lines;//number of total logs
   int arr_uids_denied[lines];//hold denied arr_uids
   
   int k =0;
   
   for(int i =0;i<num_of_logs;i++)/*GET ALL UIDS THAT ARE DENIED******************************/
   {
  	if(arr_entry[i].action_denied==1)
  	{       
       arr_uids_denied[k]=arr_entry[i].uid;
       k++;
       }
   }


/*get individual uid on an array************************************************/
    int length = k;    
    int fr[length];    
    int visited = -1;    
    int arr_uids_denied_indiv[k];     
    for(int i = 0; i < length; i++){    
        int count = 1;    
        for(int j = i+1; j < length; j++){    
            if(arr_uids_denied[i] == arr_uids_denied[j]){  
              
                count++;    
                fr[j] = visited;   
                 
            }    
        }    
        if(fr[i] != visited)    
            fr[i] = count;    
    }    
        int index=0;
    for(int i = 0; i < length; i++){    
        if(fr[i] != visited){    
     
            arr_uids_denied_indiv[index]=arr_uids_denied[i];
            index++;
        
        }    
    }    

/*FOR EVERY INDIVIDUAL UID GET THE FILE WHICH IS ALSO ACTION DIENIED**************************************/
   
    int index2=0;
    struct entry_file arr_entry_file[lines];
    arr_entry_file[0].file='\0';
    int p=0;
   
    for(int i = 0;i < index;i++)//for every individual uid
    {

            for(int j = 0; j < lines;j++)//go to every log file line
            {
       
                    if((arr_uids_denied_indiv[i]==arr_entry[j].uid))//check if uid the sa,e
                    {
                            if(arr_entry[j].action_denied==1)//check if action_denied flag is 1
                            {
                            arr_entry_file[index2].file=(char *)malloc(strlen(arr_entry[j].file));

                            strcpy(arr_entry_file[index2].file,arr_entry[j].file);
                            index2++;
                            p++;
                            }
                    }
            }
   
    int length2 = index2;   
    int fr2[length2];  
    int visited2 = -1;  
     
  //*get number of action denied accesses of different files INDIVIDUAL with uids *********************************************/
    for(int i = 0; i < length2; i++){    
        int count2 = 1;    
        for(int j = i+1; j < length2; j++){    
            if(strcmp(arr_entry_file[i].file,arr_entry_file[j].file)==0){    
                count2++;      
                fr2[j] = visited2;    
            }    
        }    
        if(fr2[i] != visited2)    
            fr2[i] = count2;    
    }  
    
    int number_of_modifications=0;
    for(int k = 0; k < length2; k++){   
    
        if(fr2[k] != visited2){    
           number_of_modifications++;
            
        }    
    }
/*PRINT TO SCREEN-USER OUTPUT***********************************************************/
if(number_of_modifications >= 7){
    printf("Uid:%d | Number of different action denied files:%d\n",arr_uids_denied_indiv[i],number_of_modifications);
    }
    

/*cLEAR EVERYTHING AND START AGAIN FROM NEW UID************************************************/
	for(int l = 0; l<index2;l++)
	{
	arr_entry_file[l].file='\0';
	}
	index2=0;
	number_of_modifications=0;
            
    }   
  
   
     
 
    fclose(file);


}


void
list_file_modifications(FILE *log, char *file_to_scan)
{

int log_size=getFileSize("/var/tmp/file_logging.log");//get log file size
char * log_text = (char * )malloc(log_size);
log_text=  returnPlainText(log_text);//get log file plain text
FILE* file = fopen("/var/tmp/file_logging.log", "r"); /* should check the result */

   int line_number = 0;
   int size_of_line=0;
   char * log_entry = (char * )malloc(21);
   char * line_array = (char * )malloc(log_size);
   line_number=getLineNumber(line_array,log_size,file);//get line number

     
      struct entry arr_entry[line_number];//insert the logs in the array of structures
    
      FILE* file2 = fopen("/var/tmp/file_logging.log", "r");
       char * line_array2 = (char * )malloc(log_size);
 
   int lines=0;
    while (fgets(line_array2, log_size, file2)) {//get line number

	size_of_line=strlen(line_array2);//get size of line
	
	


	
	if(strncmp(line_array2,"UID:",strlen("UID:"))==0)
	{

	for(int i = 0 ;i < 3;i++)
		{
		log_entry[i]=line_array2[i];
		}

	int strct_uid = 0;
	int first_char=strlen("UID:");
	int last_char = strlen(line_array2);
	char arr_uid[last_char-first_char];
	
	int k = 0;
	for(int i =first_char;i<=last_char;i++)
	{
	
	arr_uid[k]=line_array2[i];

	
	
	k++;
	}
	
	arr_entry[lines].uid=atoi(arr_uid);

	fgets(line_array2, log_size, file2);
	
	
	
	}
	

	if(strncmp(line_array2,"File name:",strlen("File name:"))==0)
	{


		for(int i = 0 ;i < 9;i++)
		{
		log_entry[i]=line_array2[i];
		}

	int strct_filename = 0;
	int first_char=strlen("File name:");
	int last_char = strlen(line_array2);
	char arr_filename[last_char-first_char];
	
	int k = 0;
	for(int i =first_char;i<=last_char;i++)
	{
	arr_filename[k]=line_array2[i];
	
	k++;
	
	}

	
	

	arr_entry[lines].file=(char * )malloc(k);
	strcpy(arr_entry[lines].file,arr_filename);
	
       
	fgets(line_array2, log_size, file2);
	

	}

	if( strncmp(line_array2,"Date:",strlen("Date")+1)==0)
	{

		for(int i = 0 ;i < 4;i++)
		{
		log_entry[i]=line_array2[i];
		}
	
	

	int strct_date = 0;
	int first_char=strlen("Date:");
	int last_char = strlen(line_array2);
	char arr_date[last_char-first_char];
	
	int k = 0;
	for(int i =first_char;i<=last_char;i++)
	{
	arr_date[k]=line_array2[i];
	
	k++;
	}
	
	
	arr_entry[lines].date=(char * )malloc(k);
	strcpy((char *)arr_entry[lines].date,(const char *)arr_date);

	fgets(line_array2, log_size, file2);


	}
	
	//ee
	
	
	if(strncmp(line_array2,"Timestamp:",strlen("Timestamp:"))==0)
	{

		for(int i = 0 ;i < 9;i++)
		{
		log_entry[i]=line_array2[i];
		}
	

	int strct_timestamp = 0;
	int first_char=strlen("Timestamp:");
	int last_char = strlen(line_array2);
	char arr_timestamp[last_char-first_char+1];
	
	int k = 0;
	for(int i =first_char;i<=last_char;i++)
	{
	arr_timestamp[k]=line_array2[i];
	
	k++;
	}
	
	arr_entry[lines].time=(char * )malloc(k);
	strcpy((char *)arr_entry[lines].time,(const char *)arr_timestamp);
	


	fgets(line_array2, log_size, file2);

	}

	if(strncmp(line_array2,"Access Type:",strlen("Access Type:"))==0)
	{

		for(int i = 0 ;i < 11;i++)
		{
		log_entry[i]=line_array2[i];
		}
	

	int strct_access_type = 0;
	int first_char=strlen("Access Type:");
	int last_char = strlen(line_array2);
	char arr_access_type[last_char-first_char+1];
	
	int k = 0;
	for(int i =first_char;i<=last_char;i++)
	{
	arr_access_type[k]=line_array2[i];
	
	k++;
	}
	
	
	arr_entry[lines].access_type=atoi(arr_access_type);
	fgets(line_array2, log_size, file2);

	

	}
	
	if(strncmp(line_array2,"Is-action-denied flag:",strlen("Is-action-denied flag:"))==0){
	
		for(int i = 0 ;i < 21;i++)
		{
		log_entry[i]=line_array2[i];
		}
	
	


	int strct_action_denied = 0;
	int first_char=strlen("Is-action-denied flag:");
	int last_char = strlen(line_array2)-1;
	char arr_action_denied [last_char-first_char];
	
	int k = 0;
	for(int i =first_char;i<=last_char;i++)
	{
	arr_action_denied [k]=line_array2[i];
	k++;
	}
	
	
	arr_entry[lines].action_denied=atoi(arr_action_denied );
	fgets(line_array2, log_size, file2);
	
	}
	if(strncmp(line_array2,"File fingerprint:",strlen("File fingerprint:"))==0) 
	             {
	         for(int i = 0 ;i < 18;i++)
		{
		log_entry[i]=line_array2[i];
		}
	

	int strct_fingerprint = 0;
	int first_char=strlen("File fingerprint:");
	int last_char = strlen(line_array2);
	char arr_fingerprint[last_char-first_char];
	int k = 0;


	for(int i =first_char;i<=last_char;i++)
	{

	arr_fingerprint[k]=line_array2[i];
	
	k++;
	}

	
	arr_entry[lines].fingerprint=(char * )malloc(k);
	strcpy(arr_entry[lines].fingerprint,arr_fingerprint);
	}
	
        lines++;
	
    }
     printf("\n************************************************************************");
 
      
/***GET ALL UIDS IN THE FILE file_to_scan*******************/    
  int  k = 0; 
  int index_uid=0;   
  int *uids=(int *)malloc(lines*4);   
  struct entry_fing arr_entry_fing[line_number];


for(int i= 0 ; i< lines;i++)
{

char * help_file =(char * )malloc(strlen(arr_entry[i].file));
strcpy(help_file, arr_entry[i].file);
int len = strlen(arr_entry[i].file)-strlen(file_to_scan)-1;
char help_file2[len];
help_file2[0]='\0';

for(int j = len; j< strlen(arr_entry[i].file);j++)//copy from fullpath only the file to help_file2
{
  
        help_file2[k]=help_file[j];
        k++;
        if(k==strlen(file_to_scan))
        {
                k=0;
                break;
        }
        
}
help_file2[strlen(file_to_scan)]='\0';
if( strcmp(file_to_scan,help_file2)==0 )//get all uids of this file
{
uids[index_uid]=arr_entry[i].uid;

index_uid++;
}



}


/*GET ALL INDIVIUAL USERS IN AN THE ARRAY OF USERS WITH THAT FILE*************************************************/
    int length = index_uid;    
    index_uid=0;
        

    int fr[length];    
    int visited = -1;    
        
    for(int i = 0; i < length; i++){    
        int count = 1;    
        for(int j = i+1; j < length; j++){    
            if(uids[i] == uids[j]){   

                count++;    
                fr[j] = visited;    
            }    
        }    
        if(fr[i] != visited)    
            fr[i] = count;    
    }    
    int * uids_individual=(int *)malloc(length*4);
    int l = 0;

   
    for(int t = 0; t< length; t++){    
        if(fr[t] != visited){   
       
            uids_individual[l]=uids[t];             
            l++; 
            
           
        }    
    }    

int index=0; 
struct entry_fing2 arr_entry_fing2[lines];

/*FOR EACH INDIVIDUAL USER CHECK NUMBER OF DIFFERENT FINGERPRINTS*******************/
for(int i = 0;i<l;i++)
{


	for(int j = 0;j<lines;j++)
	{
	

		if(uids_individual[i]==arr_entry[j].uid)
		{
		        
		       

                      
                char * help_filex =(char * )malloc(strlen(arr_entry[j].file));
                strcpy(help_filex, arr_entry[j].file);//copy to help_file the fullpath
                int lenx = strlen(arr_entry[j].file)-strlen(file_to_scan)-1;

                char help_file2x[lenx];
                help_file2x[0]='\0';
                 k =0;
                for(int n = lenx; n< strlen(arr_entry[i].file);n++)
                {
                        
                        help_file2x[k]=help_filex[n];

                        k++;
                        if(k==strlen(file_to_scan))
                        {
                                break;
                        }
                        
                }
                help_file2x[strlen(file_to_scan)]='\0';
             //  printf("\n%s",help_file2x);
                if( strcmp(file_to_scan,help_file2x)==0 )
                {

                      
		arr_entry_fing2[index].fingerprint=(char * )malloc(strlen(arr_entry[j].fingerprint));
		
		strcpy(arr_entry_fing2[index].fingerprint,arr_entry[j].fingerprint);

		index++;
		
		}
		
		}

	}

    int length2 = index;    
          
    int fr2[length2];    
    int visited2 = -1;    
        
    for(int i = 0; i < length2; i++){    
        int count2 = 1;    
        for(int j = i+1; j < length2; j++){    
            if(strcmp(arr_entry_fing2[i].fingerprint,arr_entry_fing2[j].fingerprint)==0){    
                count2++;  
                  

                fr2[j] = visited2;    
            }    
        }    
        if(fr2[i] != visited2)    
            fr2[i] = count2;    
    }    

    int number_of_modifications=0;

    for(int p = 0; p < length2; p++){    
        if(fr2[p] != visited2){    
           number_of_modifications++;

        }
        if(p==length2-1)
        {
                printf("\nuserid:%d |  number  of modifications:%d",uids_individual[i],number_of_modifications);
            
        }    
    }   
     

	for(int i = 0; i<index;i++)
	{

	arr_entry_fing2[i].fingerprint='\0';

	
	}
	index=0;

}
     printf("\n************************************************************************");
    fclose(file);
	return;

}



int 
main(int argc, char *argv[])
{

	int ch;
	FILE *log;

	if (argc < 2)
		usage();

	log = fopen("/var/tmp/file_logging.log", "r");
	if (log == NULL) {
		printf("Error opening log file \"%s\"\n", "./log");
		return 1;
	}

	while ((ch = getopt(argc, argv, "h:i:m")) != -1) {
		switch (ch) {		
		case 'i':
		      
			list_file_modifications(log, optarg);
			break;
		case 'm':
		        
			list_unauthorized_accesses(log);
			break;
		default:
			usage();
		}

	}
	
	
	
	

	
	/* add your code here */
	/* ... */
	/* ... */
	/* ... */
	/* ... */


	fclose(log);
	argc -= optind;
	argv += optind;	
	
	return 0;
}
