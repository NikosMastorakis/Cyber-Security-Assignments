Basic ransomware implementation
"gcc --verion" output:
gcc (Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0

MASTORAKIS NIKOLAOS


In this assigment all the tasks where implemented successfully.


Ransomware usage:
        
To check the implementation of my program I created a menu in the ransomware.sh file.When running ./ransomware.sh in the terminal a menu pops up.The options you can choose are the following:

1)Option one lets you input the name of the directory in which you want to create a volume of files.After typing the name of the directory you can input the number of files to be created.

2)In option 2 at first you type the directory in which are the files you want to encrypt.After you type the name it shows you in a list all the files and then you can type the number of files to encrypt from the start of the file.At the end this file discards the original files and keeps only the encrypted

3)In option 3 you enter the name of the directory in which are the files you want to decrypt and then you can type the number of files to decrypt.

4)Option 4 is a combination of option 1 and 2.You give as input the directory name and number of files to be created and then it autoencrypts the files and deletes the original files

To exit the menu you can press any other key


Function implementation

ransomware.sh implementation:
At the start I created a menu and when the user chooses one option a specific function is called that is responsible for the operation of this option.
When the program starts and before the menu pops up the make command runs to generate all the appropriate .o files.

The way I managed to get the log files of the openssl encryption and decryption is by loading to the LD_PRELOAD the command for encryption(and decryption each time) and creating a new function to my logger.so library.The function was fopen64.The function fopen64 is used in openssl library in the encryption and decryption function and the difference from original fopen is that it is used for a large volume of files(large-file support version of fopen()).When an encryption is made in the file an action_type 0(opening) log is created for the .encrypted file and then there are 3 files which are of action_type 2(for writing).The readon is that the fwrite() function is used three times in function called from openssl when encrypting.

ac_monitor.c:
In this file I changed some of my functions from assigmen3.Basically I created a function returnLogStruct() which assigns to our struct the whole log entry and also assignes to a variable givven as argument the total number of lines in the log file.The struct which kept the logs was of size 'total log entry lines / 6' since each log has 6 entrys.
I also created 2 functions(number_of_files_last_twenty_minuits(),print_encrypted_files()).

number_of_files_last_twenty_minuits():
In this function after getting the log entrys in the struct I first calculated the current time and then I seperated hours minuits and seconds from the current time to compare them with the time in the log entrys.At the end of the fule after I got the total number of files created the last 20 minuits I printed.I also checked if the argument givven is less or bigger than the number of created files and if the argument was less or equal I printed a message "Indicates suspicious behavior" else I printed a message "Does not indicate suspicious behavior".

print_encrypted_files():
In this function after getting the log entrys through function "returnLogStruct" I searched for each file that had access_type=0(open flag) if there was another file .encrypt at the end which also had access_type=2 for writing and I printed it to the console the result.

returnLogStruct():
This function returned all the log entrys of the file_logging.log in a struct format and it was called in all the functions referenced above in the acmonitor file.





