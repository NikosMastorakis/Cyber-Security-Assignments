MASTORAKIS NIKOLAOS



All the tasks of Assigment 3 were implemented successfully.Bellow you can see the functions declaration and how I used it to implement the tasks of this assigment.Bellow the functions explanation you can see a menu which have different options.This options are in test_aclog() and show how I can test if all the requirements of this assigment were implemented properlly.

logger.c file explanation:
Functions
fopen:
In this function by using the LD_PRELOAD tool I managed to overwrite the fopen function.More specifically even though the fopen was used as it was supposed to I managed to keep track of some users information(uid,access_type,path,day,time,is_action_denied,fingerprint).At the start of the function I checked if the file that was given as argument to fopen already existed by using the access(path,F_OK) function.If the return value was 0 that means that file existed else it was created.By using the dlsym, command I managed to keep an original copy of the fopen function so I could return it at the end of the function.RTLD_NEXT was given as argument to dlsym because we wanted to overwrite the fopen and instead of executing immediately the original function first the programm would find the next occurence of the desired symbol in the search order after the current object which was the original fopen.In the rest of code in fopen function I checked if the file was "file_logging.log" and if it was I returned the original_fopen and if it was not I checked If the user had access writes to open the file.The way I checked for access writes was with the help of erno .If the value of erno was equal to EACCESS that would mean that the is_action_denied should be set to 1.After checking the access rights I set the rest of the log entrys I needed to implement to log file(day,time,uid,fingerprint,filename).

fwrite:
This function was similar to fopen.The differences were the following.First of all the I managed to get the fullpath of the file with the of the file descriptor.Secondly I checked if the file I wanted to write was file_logging and if it was that means that I returned the original fwrite.After getting all the users information for the log file I passed this information to writeToLog function so i could write them to the log file.Inside writeToLog after every fprintf() I used fflush so I could guarantee that the buffer is emptied since sometimes without fflush() the programm would crash.

add_spaces:
This function adds space nexto to a string.This function is used to modifyText() function which changes a char* type of variable and in remove_read_write_permissions() function which removes read and write permission of a givern filename(char *)

remove_read_write_permissions():
This function removes the read write permissions of a file by calling system function so we can run the chmod command and modify users permissions in a file.

delete_files():
This function is used to delete a file by calling the rm command with the help of the system function.

acmonitor.c file explanation:

getLineNumber():Returns total number of lines.

list_unauthorized_access():
Purpose of this function was to print the users who accessed more than 7 different files.At first I get all the "file_logging.log" information inside a while loop until fgets() doesnt have other lines to read and copy all the information from each log entry in a an array of type struct entry.I also hold in a variable named lines the total number of lines in the log file so I can use it as index to the correct stuct array index. After I  fill that array I get all the uids of users who have action)denied=1.After getting all the uids in an array because this array may have multiple times the same uid I manage to get only time each uid in the arr_uids_denied_indiv array.After feeling arr_uids_denied_indiv array I get the filenames which the user tried fopen without having permission and I print the results at the screen.

list_file_modifications():
This function was responsible print a table about which users have modified a given file and how many times by comparing files fingerprints before and after file modification.At start I got all to log entries in an array of structs like I did in the list_unathorized_access() function.After getting them I got the file_name given as argument and got all the user id with that file name in file path on the log files.The array uids[] had all the uid of users who modiefied the file.The problem was that. this array may have the same user uid multiple times.For this reason I filtered the array and put the different user uids one time in the array uids_individual.After getting the uids one time for each file I got the number of fingerprints of each user for this specific file and after this I printed the final table which was the userid | number of modifications.

TESTING OF ASSIGMENT


At test_aclog. I implemented a menu which illustrates the correct usage of logger.c.

1)Using fopen to open a file that does not exist to check if action_type is 0.
2)Using fopen to open a file that  does not exist and then opening again the same file to check if action_type is 1 after opening a file that is already created
3)Creating 10 files with read and write permissions and then writing to them to check the action_type which should be 2 after writing to a file and also check if the fingerprints change after writing(modifying) a file.
4)Creating 10 files and removing access rights(chmod -wr filename).Then we try to write to the file to check if is_action_denied is 1 after trying to write to the them.
5)Creating 10 files and write to each file 2 times.After checking the logs I checked if fingerprints change after the users tries to write two times to te same file.

6)After choosing this option you must run ./acmonitor -m and check the output that prints malicious users that tried to access 7 different files without having permission.You can see in the output the table with the userid and the number of times he tried to access this file.

7)After choosing this option you must run ./acmonitor -m and check the output.The output does not print anything because the user only tried to access 6 different files without having permissions.You can see the output only if the number of denied accesses is at least 7

8)After choosing this option you must run ./acmonitor -i filename where filename is file_0,file_1,file_2,file_5,file_7 and file_8 to check the uid and number of modifications.

Option 9,10,11,12,13 and 14 are used to check if fopen function works successfully for all the modes r,w,ar+,w+,a+.

15)Option 15 checks the case where a log is created because a user tried to fopen with r mode in a file that does not exist.

If you try to test option 7,delete file_logging.txt file before so it doesnt have any log entries.

(After the users chooses which option of the menu he wants to execute and after the file_logging.log file is updated with the new information ,all the files that were generated at that option were deleted because they are used only for testing purposes so we can see after execution the log file.)

The file "file_logging." is save in a directory which is accessible from all users.This is the /var/tmp file.Files in /var/tmp are supposed to be world-writable so that all programs can create their temporary files there.

By running gcc --version i get the following output:
gcc (Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0


