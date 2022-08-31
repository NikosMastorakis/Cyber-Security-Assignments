#define _GNU_SOURCE

#include <time.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/md5.h>
#include <time.h>
#include<sys/stat.h>
#include<time.h>
#include <errno.h>
#include<signal.h>

void writeToLog(FILE * log_file,char * uid_string,char * fullpath,char * time_of_modif,char * date_of_modif,
	char * access_type_string,char * is_action_denied_string,char * fingerprint_string);





//when file opens -> log entry for fopen
//when fopen and fwrite -> 1 log entry for fopen and 1 log entry for fwrite
//if read and not permission -> 1 log entry
//if fopen(w) and not permission -> 1 log entry 
//if fopen(w) and fwrite() and not permission -> 1 log entry for fopen 
//if fopen(r) without existing file -> 0 log entrys segmentation
//if fwrite(r) without fopen  -> 0 log entrys segmentation segmentation
/**
 * Main idea:
 * Check if file exists or not (access_type)
 * Check if fopen is for opening and writing file_logging.log(return original fopen
 * Check if action denied(with ERRNO))
 * IF access is permitted read content to create MD5 fingerprint
 * Else create a null fingerprint with md5
 * Append to file_logging(uid,time,day....)
 * return original open to actually open the file
 * 
 */
FILE *
fopen(const char *path, const char *mode) 
{

	int is_action_denied=0;
   	int access_type=0;
   	
   	if( access( path, F_OK ) == 0 ) {//file exists
   	access_type=1;
   	}
   	if( access( path, F_OK ) != 0 ) {//file not exists
  
   	access_type=0;
   	}
   	
   	
	/* Standard code for overwriting functions but still FUNCTION normally*/
	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);

	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)(path, mode);
	
	
	
	
	
	
 	if(strcmp(path,"/var/tmp/file_logging.log") == 0)//if fopen on file_logging.log
 	{

 	
 	return original_fopen_ret;
 	}
 	else{
 	      


	if(errno == EACCES) { //if user has no permission for fopen
		is_action_denied = 1;
	
	}
	
	

	
	char * access_type_string = (char * )malloc(1);//convert access_type and is_action_denied to string
	sprintf(access_type_string,"%d",access_type);
	char * is_action_denied_string = (char * )malloc(1);
	sprintf( is_action_denied_string,"%d", is_action_denied);
	
	unsigned int uid = getuid();//UID
	char * uid_string = (char * )malloc(65536);
	sprintf(uid_string,"%d",uid);
	
	char *fullpath=realpath("./",NULL);//FULL PATH NAME
	strcat(fullpath,"/");
	strcat(fullpath,path);

	time_t T = time(NULL);//DAY
   	struct tm tm = *localtime(&T);
   	char buffer_mday[4];
   	char buffer_mon[4];
   	char buffer_year[4];
   	sprintf(buffer_mday,"%d",tm.tm_mday);
   	sprintf(buffer_mon,"%d",tm.tm_mon+1);
   	sprintf(buffer_year,"%d",tm.tm_year + 1900);
   	char date_of_modif[
   	strlen(buffer_mday)+
   	strlen("/") + 
   	strlen(buffer_mon)+
   	strlen("/") + 
   	strlen(buffer_year)
   	];
   	date_of_modif[0]='\0';
   	strcat(date_of_modif,buffer_mday);
   	strcat(date_of_modif,"/");
   	strcat(date_of_modif,buffer_mon);
   	strcat(date_of_modif,"/");
   	strcat(date_of_modif,buffer_year);
   	char * date_of_modif_string = (char * )malloc(strlen(date_of_modif));
	sprintf( date_of_modif_string,"%s",  date_of_modif);

   	char buffer_hour[4];//TIME
   	char buffer_min[4];
   	char buffer_sec[4];
   	sprintf(buffer_hour,"%d",tm.tm_hour);
   	sprintf(buffer_min,"%d",tm.tm_min);
   	sprintf(buffer_sec,"%d",tm.tm_sec);
   	char time_of_modif[
   	strlen(buffer_hour)+
   	strlen(":") + 
   	strlen(buffer_min)+
   	strlen(":") + 
   	strlen(buffer_sec)];
   	time_of_modif[0]='\0';
   	strcat(time_of_modif,buffer_hour);
   	strcat(time_of_modif,":");
   	strcat(time_of_modif,buffer_min);
   	strcat(time_of_modif,":");
   	strcat(time_of_modif,buffer_sec);
   	char * time_of_modif_string = (char * )malloc(strlen(time_of_modif));
	sprintf( time_of_modif_string,"%s",  time_of_modif);
	
	     
        char * buf_read;
        long size = 0;
        //check if fopen without file existing and if it has permission to read
	if(is_action_denied == 0 && !(access_type==0 && (strcmp(mode,"r")==0 || strcmp(mode,"+r")==0 ))){
	FILE* f ;
	f =  original_fopen(path,"r");//get file size
	fseek(f, 0, SEEK_END);
   	size = ftell(f);
   	fclose(f);
   	
        buf_read = (char * )malloc(size);//read file content and fill buffer buf_read
        FILE *f_read;
        f_read = original_fopen(path, "r");
        buf_read[0]='0';
	 for(int i = 0; i< size;i++)
 	 {

  	 fread(&buf_read[i],1,1,f_read);
  	 }
  	 
  	 fclose(f_read);
  	
  	 }
  	 else//if fopen is denied
  	 {
  	 buf_read = (char * )malloc(size);//buf_read is null to encrypt null data(md5)

  	 }

  	   unsigned char digest[16];//md5 encryption
	   char *fingerprint = (char*)malloc(size);
	   MD5_CTX c;
	   MD5_Init(&c);
	   MD5_Update(&c, buf_read, size);
	   MD5_Final(digest, &c);
	    for (int n = 0; n < 16; ++n)//convert to hexadecimal to input to log file
	   {
	     sprintf(&fingerprint[n], "%02x", (unsigned int)digest[n]);
	   }
      
      
      //if first time opening or file empty or does not have permission -> fingerprint:0
	if(is_action_denied==1 || (access_type==0 && strcmp(mode,"r")==0) ){
	FILE* log_file2 = original_fopen("/var/tmp/file_logging.log", "a");//write to log file
	writeToLog(
	log_file2,
	uid_string,
	 fullpath,
	time_of_modif_string,
	date_of_modif_string,
	access_type_string,
	is_action_denied_string,
	"0");
	
	
	            
	}
	
       else{
	FILE* log_file2 = original_fopen("/var/tmp/file_logging.log", "a");
	writeToLog(
	log_file2,
	uid_string,
	 fullpath,
	time_of_modif_string,
	date_of_modif_string,
	access_type_string,
	is_action_denied_string,
	fingerprint);
	
	}
	
	

	return original_fopen_ret;
	}
	return original_fopen_ret;
}

  /*
         * Main idea
         * File already exists else fopen would return error
         * Acess_type because write is always 0
         * Check if we have permission(ERNO)
         * Get file name full path with file descriptor
         * Get uid,time,day...
         * Get contents to write through arguments
         * fopen file for file_logging.log to append 1 log
         * return original fwrite to actually write to the file
 */


size_t 
fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) 
{
        
        int is_action_denied=0;//action is permitted
        char * is_action_denied_string = (char * )malloc(1);
        sprintf( is_action_denied_string,"%d", is_action_denied);
	        
   	
        int access_type = 2;//access type in fwrite always 2
        char * access_type_string = (char * )malloc(1);
	sprintf(access_type_string,"%d",access_type);

        /* call the original fwrite function */

	size_t original_fwrite_ret;
	size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);
	
        
	original_fwrite = dlsym(RTLD_NEXT, "fwrite");
	original_fwrite_ret = (*original_fwrite)(ptr, size, nmemb, stream);
	
	
	if(errno == EACCES) { //if user has no permission for fopen
	//printf("\nERNO==EACESS");
		is_action_denied = 1;
	
	}
	
	
	
	/*get fullpath name from file description of arguments*/
	char proclnk1[0xFFF];
 	int MAXSIZE1 = 0xFFF;
 	char filename1[0xFFF];
	int fno1 = fileno(stream);
	
	sprintf(proclnk1, "/proc/self/fd/%d", fno1);
	ssize_t r1 = readlink(proclnk1, filename1, MAXSIZE1);
	if (r1 < 0)
        {
            printf("failed to readlink\n");
            exit(1);
        }
        filename1[r1] = '\0';
        char * fullpath = (char * )malloc(strlen(filename1));
        fullpath=filename1;
        
        
        
       
 
      
   
  if(strcmp(fullpath,"/var/tmp/file_logging.log") == 0)//if trying to write to file_logging.log file
 	{

 	return original_fwrite_ret;
 	}
 	else{
 	
                if(errno == EACCES) { //if action to fwrite is not permitted
		is_action_denied=1;
		}


	unsigned int uid = getuid();//UID
	//printf("\nUID:%d",uid);
	char * uid_string = (char * )malloc(65536);
	sprintf(uid_string,"%d",uid);
	
	time_t T = time(NULL);//DAY
   	struct tm tm = *localtime(&T);
   	char buffer_mday[4];
   	char buffer_mon[4];
   	char buffer_year[4];
   	sprintf(buffer_mday,"%d",tm.tm_mday);
   	sprintf(buffer_mon,"%d",tm.tm_mon+1);
   	sprintf(buffer_year,"%d",tm.tm_year + 1900);
   	char date_of_modif[
   	strlen(buffer_mday)+
   	strlen("/") + 
   	strlen(buffer_mon)+
   	strlen("/") + 
   	strlen(buffer_year)
   	];
   	date_of_modif[0]='\0';
   	strcat(date_of_modif,buffer_mday);
   	strcat(date_of_modif,"/");
   	strcat(date_of_modif,buffer_mon);
   	strcat(date_of_modif,"/");
   	strcat(date_of_modif,buffer_year);
	char * date_of_modif_string = (char * )malloc(strlen(date_of_modif));
	sprintf( date_of_modif_string,"%s",  date_of_modif);

   	
   	char buffer_hour[4];//TIME
   	char buffer_min[4];
   	char buffer_sec[4];
   	sprintf(buffer_hour,"%d",tm.tm_hour);
   	sprintf(buffer_min,"%d",tm.tm_min);
   	sprintf(buffer_sec,"%d",tm.tm_sec);
   	char time_of_modif[
   	strlen(buffer_hour)+
   	strlen(":") + 
   	strlen(buffer_min)+
   	strlen(":") + 
   	strlen(buffer_sec)];
   	time_of_modif[0]='\0';
   	strcat(time_of_modif,buffer_hour);
   	strcat(time_of_modif,":");
   	strcat(time_of_modif,buffer_min);
   	strcat(time_of_modif,":");
   	strcat(time_of_modif,buffer_sec);
   	char * time_of_modif_string = (char * )malloc(strlen(time_of_modif));
	sprintf( time_of_modif_string,"%s",  time_of_modif);
	
	FILE *(*original_fopen)(const char*, const char*);//fopen to write to file_logging.log
        original_fopen = dlsym(RTLD_NEXT, "fopen");
        FILE* f ;
	f =  original_fopen(fullpath,"r");//get file size
	fseek(f, 0, SEEK_END);
   	size = ftell(f);
   	fclose(f);
   	char * buf_read;
        buf_read = (char * )malloc(size);//
        FILE *f_read;
        f_read = original_fopen(fullpath, "r");
        buf_read[0]='0';
	 for(int i = 0; i<size;i++)//buf_read get plaintext to encrypt(md5)
 	 {
 
  	 fread(&buf_read[i],1,1,f_read);
  	
  	 }
  	 
  	 fclose(f_read);
  	 strcat(buf_read,ptr);




	 unsigned char digest[16];//md5 encryption
	 char *fingerprint = (char*)malloc(strlen(buf_read));
	 MD5_CTX c;
	 MD5_Init(&c);
	 MD5_Update(&c, buf_read, strlen(buf_read));
	 MD5_Final(digest, &c);
	 for (int n = 0; n < 16; ++n)//convert to hex
	  {
	    sprintf(&fingerprint[n], "%02x", (unsigned int)digest[n]);
	  }
	   
	
	FILE* log_file2 = original_fopen("/var/tmp/file_logging.log", "a");
	

	if(is_action_denied==1)
	{
	        
	writeToLog(
	log_file2,
	uid_string,
	 fullpath,
	time_of_modif_string,
	date_of_modif_string,
	access_type_string,
	is_action_denied_string,
	"0");
	
	return 0;
	        
	}
	else{
	writeToLog(
	log_file2,
	uid_string,
	 fullpath,
	time_of_modif_string,
	date_of_modif_string,
	access_type_string,
	is_action_denied_string,
	fingerprint);
	}
	

	return original_fwrite_ret;
	
	}
	return original_fwrite_ret;
}


void writeToLog(FILE * log_file,char * uid_string,char * fullpath,char * time_of_modif,char * date_of_modif,
	char * access_type_string,char * is_action_denied_string,char * fingerprint_string){
	

	
	fprintf(log_file,"UID:%s\n",uid_string);
	//fprintf(log_file,"\n");
	fflush(log_file);
	fprintf(log_file,"File name:%s\n",fullpath);
	//fprintf(log_file,"\n");
	fflush(log_file);
	fprintf(log_file,"Date:%s\n",date_of_modif);
	//fprintf(log_file,"\n");
	fflush(log_file);
	fprintf(log_file,"Timestamp:%s\n",time_of_modif);
	//fprintf(log_file,"\n");
	fflush(log_file);
	fprintf(log_file,"Access Type:%s\n",access_type_string);
	//fprintf(log_file,"\n");
	fflush(log_file);
	fprintf(log_file,"Is-action-denied flag:%s\n",is_action_denied_string);
	//fprintf(log_file,"\n");
	fflush(log_file);
	fprintf(log_file,"File fingerprint:%s\n",fingerprint_string);
	fflush(log_file);
	//fprintf(log_file,"\n");
	
	
	
	



	}

