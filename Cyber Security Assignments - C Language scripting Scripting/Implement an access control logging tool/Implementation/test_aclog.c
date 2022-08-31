#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>




void add_spaces(char *dest, int num_of_spaces) {//function for creating spaces
    int len = strlen(dest);
    memset( dest+len, ' ', num_of_spaces );   
    dest[len + num_of_spaces] = '\0';
}


void remove_read_write_permissions(char * file)
{
        char *chmod = (char * )malloc(sizeof("chmod -wr"));
	char *file_name=(char*)malloc(sizeof(file));
	strcpy(chmod,"chmod -wr");
	add_spaces(chmod,1);
	strcpy(file_name,file);
	strcat(chmod,file_name);
	
	int ret = system(chmod);//execute chmode -wr filename command
	//printf("\n----%d %s ",ret,chmod);
}
void delete_files(char * file)
{
        char *rm= (char * )malloc(sizeof("rm -f"));
	char *file_name=(char*)malloc(sizeof(file));
	strcpy(rm,"rm -f");
	add_spaces(rm,1);
	strcpy(file_name,file);
	strcat(rm,file_name);
	//printf("\n %s ",chmod);
	system(rm);
}
char * modifyText(char* file)//returns string 'modified file_name'
{
        char *modified= (char * )malloc(sizeof("modified"));
	char *file_name=(char*)malloc(sizeof(file));
	strcpy(modified,"modified");
	add_spaces(modified,1);
	strcpy(file_name,file);
	strcat(modified,file_name);
	return modified;
	
        
}

int main() 
{
/*
 * The 1st time it runs creates log for fopen and action_denied log for fwrite
 * 
 * The 2nd time it runs creates log only for fopen
 * 
 * ./acmonitor -m -> must print that there are 10 different files with action_denies=1 for current user
 */
    int i;
    size_t bytes;
    FILE *file;
   char filenames[10][7] = {"file_0", "file_1", 
			                "file_2", "file_3", "file_4",
			"file_5", "file_6", "file_7", 		
			"file_8", "file_9"};
    char * file_11 = "file_11";
 int choise;


  printf("\nCheck logger.c and acmonitor.c functionality by choosing one option from bellow: ");

  printf("\n\nSTEP 1 - ACCESS CONTROL LOGIN TOOL");
  printf("\n---------------------------------------------------\n");
  printf("1) Test fopen when file does not exist with mode w+ action_type=0)");
  printf("\n2) Test fopen on an existing file (action_type of second log is 1)");
  printf("\n3) Create 10 files with read write permissions and try to write to them ");
  printf("\n4) Create 10 files.Remove read-write permissions and then try to fopen with 'w+' in 10 files: ");
  printf("\n5) Create 10 files write to them and then modify them: ");
  printf("\n\n STEP 2 - ACCESS CONTROL MONITOR LOGIN");
  printf("\n---------------------------------------------------\n");
  
  printf("6)Test list_unauthorized_accesses(User modified file 7 times,must print output).");
  printf("7)Test list_unauthorized_accesses(User modified file 6 times,must not print output).");
  printf("\n8)Test list_file_modifications(check file_0, file_1, file_2, file_5, file_7, file_8 ).");
  
  
  printf("\n\n Choose a mode for fopen");
  printf("\n---------------------------------------------------\n");
  printf("9) Try fopen with mode 'r'.");
  printf("\n10) Try fopen with mode 'w'.");
  printf("\n11) Try fopen with mode 'a'.");
  printf("\n12) Try fopen with mode 'r+'.");
  printf("\n13) Try fopen with mode 'w+'.");
  printf("\n14) Try fopen with mode 'a+'.");
  printf("\n15)Try reading a file that does not exist");
  
  
  printf("\n\n");
printf("Enter a number: ");
  
 
    scanf("%d", &choise);
            
     
   switch(choise){
            
            
	    case 1:
	           
	            file = fopen(file_11, "w+");//creation of a new file 
	            fclose(file);
		    delete_files(file_11);
		   
		    break;
	   case 2:
	            file = fopen(filenames[1], "w+");//create a file and then fopen
	            file = fopen(filenames[1], "w+");
	            delete_files(filenames[1]);
		    fclose(file);
		    break;
		    
		
		
	   case 3:
               for (i = 0; i < 10; i++) {//create 10 files
		file = fopen(filenames[i], "w+");
		bytes = fwrite(filenames[i],  1,strlen(filenames[i]), file);//write to them
		fclose(file);
		delete_files(filenames[i]);
	        }
	        break;
	      
	           
	   case 4:
	       for (i = 0; i < 10; i++) {//create 10 files
		file = fopen(filenames[i], "w+");
	        }
	        fclose(file);
               for (i = 0; i < 10; i++) {//remove permissions and fopen
               remove_read_write_permissions(filenames[i]);
		file = fopen(filenames[i], "w+");
		
		//fwrite(filenames[i],1,strlen(filenames[i]), file);
		delete_files(filenames[i]);
	   }
	   

	   break;
	   case 5:
	       for (i = 0; i < 10; i++) {//create 10 files and write to them 
	       
		file = fopen(filenames[i], "w+");
		bytes = fwrite(filenames[i],  1,strlen(filenames[i]), file);

		char * modified_text = modifyText(filenames[i]);
		bytes = fwrite(modified_text,  1,strlen(filenames[i]), file);
		
		delete_files(filenames[i]);
	   }
	   fclose(file);
	   
	   break;
	   
	   case 6:
	          for (i = 0; i < 7; i++) {//create 10 files and write to them 
	       file = fopen(filenames[i], "w+");
                remove_read_write_permissions(filenames[i]);

		file = fopen(filenames[i], "w+");
		delete_files(filenames[i]);
	   }
	   break;
	   case 7:
	          for (i = 0; i < 6; i++) {//create 10 files and write to them 
	       file = fopen(filenames[i], "w+");
                remove_read_write_permissions(filenames[i]);

		file = fopen(filenames[i], "w+");
		delete_files(filenames[i]);
	   }
	
	
	         
	       
	           break;
	   case 8:
	            file = fopen(filenames[0], "w+");
	      for(i=0;i<10;i++){
	              bytes = fwrite(filenames[i],  1,strlen(filenames[0]), file);//write to them     
	      }
	      delete_files(filenames[0]);
	    fclose(file);
	    file = fopen(filenames[1], "w+");
	      for(i=0;i<9;i++){
	              bytes = fwrite(filenames[i],  1,strlen(filenames[0]), file);//write to them     
	      }
	    delete_files(filenames[1]);
	    fclose(file);
	    file = fopen(filenames[2], "w+");
	      for(i=0;i<8;i++){
	              bytes = fwrite(filenames[i],  1,strlen(filenames[0]), file);//write to them     
	      }
	      delete_files(filenames[2]);
	    fclose(file);
	     file = fopen(filenames[5], "w+");
	      for(i=0;i<4;i++){
	              bytes = fwrite(filenames[i],  1,strlen(filenames[0]), file);//write to them     
	      }
	      delete_files(filenames[5]);
	    fclose(file);
	     file = fopen(filenames[8], "w+");
	      for(i=0;i<4;i++){
	              bytes = fwrite(filenames[i],  1,strlen(filenames[0]), file);//write to them     
	      }
	      delete_files(filenames[8]);
	    fclose(file);
	    file = fopen(filenames[7], "w+");
	      for(i=0;i<2;i++){
	       bytes = fwrite(filenames[i],  1,strlen(filenames[0]), file);//write to them     
	      }
	      delete_files(filenames[7]);
	     fclose(file);
	          break;
	     case 9:
	         file = fopen(file_11, "w");
	         fclose(file);
	         file = fopen(file_11, "r");
	         delete_files(file_11);
	         fclose(file);
	       
	           break;
	   case 10:
	           file = fopen(file_11, "w");
	           delete_files(file_11);
	           fclose(file);
	           break;
	   case 11:
	           file = fopen(file_11, "a");
	           delete_files(file_11);
	           fclose(file);
	           break;
	          
	   case 12:
	           file = fopen(file_11, "w");
	           fclose(file);
	           file = fopen(file_11, "r+");
	           delete_files(file_11);
	           fclose(file);
	           break;
	   case 13:
	           file = fopen(file_11, "w+");
	           delete_files(file_11);
	           break;
	   case 14:
	           file = fopen(file_11, "a+");
	           delete_files(file_11);
	           fclose(file);
	           break;
	   case 15:
	        
	        file = fopen("file_that_not_exists", "r");
	        break;

	
	           
	  default:
	          printf("\nEnter choise");
            
    }
       
  
	
	
	
	

}
