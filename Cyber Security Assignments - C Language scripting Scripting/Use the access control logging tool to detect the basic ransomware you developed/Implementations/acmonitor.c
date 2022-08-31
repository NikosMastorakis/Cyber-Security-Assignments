#include <time.h>

#include <stdio.h>

#include <stdlib.h>

#include <string.h>

#include <unistd.h>


struct entry {

    int uid; /* user id (positive integer) */
    int access_type; /* access type values [0-2] */
    int action_denied; /* is action denied valuees [0-1] */

    char * date; /* file access date */
    char * time; /* file access time */

    char * file; /* filename (string) */
    char * fingerprint; /* file fingerprint */

    /* add here other fields if necessary */
    /* ... */
    /* ... */

};
struct entry_fing {

    int uid; /* user id (positive integer) */
    char * file; /* filename (string) */
    char * fingerprint; /* file fingerprint */

    /* add here other fields if necessary */
    /* ... */
    /* ... */

};

struct entry_fing2 {

    char * fingerprint; /* file fingerprint */

    /* add here other fields if necessary */
    /* ... */
    /* ... */

};
struct entry_file {

    char * file; /* filename (string) */

    /* add here other fields if necessary */
    /* ... */
    /* ... */

};

char * get_current_time() {
    time_t T = time(NULL);
    struct tm tm = * localtime( & T);
    char buffer_hour[4]; //TIME
    char buffer_min[4];
    char buffer_sec[4];
    sprintf(buffer_hour, "%d", tm.tm_hour);
    sprintf(buffer_min, "%d", tm.tm_min);
    sprintf(buffer_sec, "%d", tm.tm_sec);
    char time_of_modif[
        strlen(buffer_hour) +
        strlen(":") +
        strlen(buffer_min) +
        strlen(":") +
        strlen(buffer_sec)];
    time_of_modif[0] = '\0';
    strcat(time_of_modif, buffer_hour);
    strcat(time_of_modif, ":");
    strcat(time_of_modif, buffer_min);
    strcat(time_of_modif, ":");
    strcat(time_of_modif, buffer_sec);
    char * time_of_modif_string = (char * ) malloc(strlen(time_of_modif));
    sprintf(time_of_modif_string, "%s", time_of_modif);

    return time_of_modif_string;

}

int getLineNumber(char * line_array, int log_size, FILE * file) //get number of lines in file
{
    int line_number;
    while (fgets(line_array, log_size, file)) {
        line_number++;
    }
    return line_number;
}

void
usage(void) {
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
char * returnPlainText(char * buf) //return file plaintext
{
    size_t k = 0; //get file size
    FILE * fIN2;
    fIN2 = fopen("/var/tmp/file_logging.log", "r");
    fseek(fIN2, 0L, SEEK_END);
    int sz = ftell(fIN2);
    fclose(fIN2);

    FILE * fIN; //Get loggin plain text into buf1
    fIN = fopen("/var/tmp/file_logging.log", "r");
    char * buf1 = (char * ) malloc(sz);
    if (fIN == NULL) {
        printf("File is not available \n");
    } else {

        char ch;
        while ((ch = fgetc(fIN)) != EOF) {

            buf1[k] = ch;

            k++;

            if (k == sz) {
                break;
            }
        }

    }
    fclose(fIN);
    return buf1;

}
int getFileSize(char * input_file) //get file size function
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

void returnLogStruct(struct entry * arr_entry, int * lines) {
    if (access("/var/tmp/file_logging.log", F_OK) == 0) {
        // file exists

        int log_size = getFileSize("/var/tmp/file_logging.log");
        char * log_text = (char * ) malloc(log_size);
        log_text = returnPlainText(log_text);
        FILE * file = fopen("/var/tmp/file_logging.log", "r");

        int line_number = 0;
        int size_of_line = 0;
        char * log_entry = (char * ) malloc(21);
        char * line_array = (char * ) malloc(log_size);
        line_number = getLineNumber(line_array, log_size, file);

        fclose(file);

        FILE * file2 = fopen("/var/tmp/file_logging.log", "r");
        char * line_array2 = (char * ) malloc(log_size);

        int index = 0;
        while (fgets(line_array2, log_size, file2)) {

            size_of_line = strlen(line_array2);

            if (strncmp(line_array2, "UID:", strlen("UID:")) == 0) {

                for (int i = 0; i < 3; i++) {
                    log_entry[i] = line_array2[i];
                }
                int strct_uid = 0;
                int first_char = strlen("UID:");
                int last_char = strlen(line_array2);
                char arr_uid[last_char - first_char];

                int k = 0;
                for (int i = first_char; i <= last_char; i++) {

                    arr_uid[k] = line_array2[i];

                    k++;
                }

                arr_entry[index].uid = atoi(arr_uid);
                line_array[0] = '\0';
                fgets(line_array2, log_size, file2);

            }
            if (strncmp(line_array2, "File name:", strlen("File name:")) == 0) {

                for (int i = 0; i < 9; i++) {
                    log_entry[i] = line_array2[i];
                }
                //printf("\nline array: %s",&line_array2[9]);

                arr_entry[index].file = (char * ) malloc(strlen( & line_array2[9]));
                strncpy(arr_entry[index].file, & line_array2[9], strlen( & line_array2[9]));
                //line_array[0]='\0';
                fgets(line_array2, log_size, file2);

            }

            if (strncmp(line_array2, "Date:", strlen("Date") + 1) == 0) {

                for (int i = 0; i < 4; i++) {
                    log_entry[i] = line_array2[i];
                }

                int strct_date = 0;
                int first_char = strlen("Date:");
                int last_char = strlen(line_array2);
                char arr_date[last_char - first_char];

                int k = 0;
                for (int i = first_char; i <= last_char; i++) {
                    arr_date[k] = line_array2[i];

                    k++;
                }

                arr_entry[index].date = (char * ) malloc(k);
                strcpy((char * ) arr_entry[index].date, (char * ) arr_date);
                line_array[0] = '\0';
                fgets(line_array2, log_size, file2);

            }

            if (strncmp(line_array2, "Timestamp:", strlen("Timestamp:")) == 0) {

                for (int i = 0; i < 9; i++) {
                    log_entry[i] = line_array2[i];
                }

                int strct_timestamp = 0;
                int first_char = strlen("Timestamp:");
                int last_char = strlen(line_array2);
                char arr_timestamp[last_char - first_char + 1];

                int k = 0;
                for (int i = first_char; i <= last_char; i++) {
                    arr_timestamp[k] = line_array2[i];

                    k++;
                }

                arr_entry[index].time = (char * ) malloc(k);
                strcpy(arr_entry[index].time, arr_timestamp);

                line_array[0] = '\0';
                fgets(line_array2, log_size, file2);

            }

            if (strncmp(line_array2, "Access Type:", strlen("Access Type:")) == 0) {

                for (int i = 0; i < 11; i++) {
                    log_entry[i] = line_array2[i];
                }

                int strct_access_type = 0;
                int first_char = strlen("Access Type:");
                int last_char = strlen(line_array2);
                char arr_access_type[last_char - first_char + 1];

                int k = 0;
                for (int i = first_char; i <= last_char; i++) {
                    arr_access_type[k] = line_array2[i];

                    k++;
                }

                arr_entry[index].access_type = atoi(arr_access_type);
                line_array[0] = '\0';
                fgets(line_array2, log_size, file2);

            }

            if (strncmp(line_array2, "Is-action-denied flag:", strlen("Is-action-denied flag:")) == 0) {

                for (int i = 0; i < 21; i++) {
                    log_entry[i] = line_array2[i];
                }

                int strct_action_denied = 0;
                int first_char = strlen("Is-action-denied flag:");
                int last_char = strlen(line_array2) - 1;
                char arr_action_denied[last_char - first_char];
                for (int i = 0; i < strlen(line_array2); i++) {

                }

                int k = 0;
                for (int i = first_char; i <= last_char; i++) {
                    arr_action_denied[k] = line_array2[i];
                    k++;
                }

                arr_entry[index].action_denied = atoi(arr_action_denied);
                line_array[0] = '\0';
                fgets(line_array2, log_size, file2);

            }
            if (strncmp(line_array2, "File fingerprint:", strlen("File fingerprint:")) == 0) {
                for (int i = 0; i < 18; i++) {
                    log_entry[i] = line_array2[i];
                }

                //set fingerprint
                //printf("\nIS FINGERPRINT");
                int strct_fingerprint = 0;
                int first_char = strlen("File fingerprint:");
                int last_char = strlen(line_array2);
                char arr_fingerprint[last_char - first_char];
                int k = 0;

                for (int i = first_char; i <= last_char; i++) {

                    arr_fingerprint[k] = line_array2[i];

                    k++;
                }

                arr_entry[index].fingerprint = (char * ) malloc(k);
                strcpy(arr_entry[index].fingerprint, arr_fingerprint);

            }

            index = index + 1;
            //printf("\n %d",index);
        }
        * lines = index;
        fclose(file);
    } else {
        printf("\nLog file does not exist in /var/tmp/file_logging.log");
    }

}

void
list_unauthorized_accesses(FILE * log) {

    if (access("/var/tmp/file_logging.log", F_OK) == 0) {
        // file exists

        int num = 0;
        int log_size = getFileSize("/var/tmp/file_logging.log");

        FILE * file = fopen("/var/tmp/file_logging.log", "r");

        char * line_array = (char * ) malloc(log_size);
        int line_number = getLineNumber(line_array, log_size, file);

        struct entry arr_entry[line_number / 7];
        int lines = 0;
        if (log_size != 0) {
            returnLogStruct(arr_entry, & lines);
        }

        int array_of_uid; //
        int num_of_logs = lines; //number of total logs
        int arr_uids_denied[lines]; //hold denied arr_uids

        int k = 0;

        for (int i = 0; i < num_of_logs; i++) {
            if (arr_entry[i].action_denied == 1) {
                arr_uids_denied[k] = arr_entry[i].uid;
                k++;
            }
        }

        int length = k;
        int fr[length];
        int visited = -1;
        int arr_uids_denied_indiv[k];
        for (int i = 0; i < length; i++) {
            int count = 1;
            for (int j = i + 1; j < length; j++) {
                if (arr_uids_denied[i] == arr_uids_denied[j]) {

                    count++;
                    fr[j] = visited;

                }
            }
            if (fr[i] != visited)
                fr[i] = count;
        }
        int index = 0;
        for (int i = 0; i < length; i++) {
            if (fr[i] != visited) {

                arr_uids_denied_indiv[index] = arr_uids_denied[i];
              
                index++;

            }
        }

        int index2 = 0;
        struct entry_file arr_entry_file[lines/7];
        arr_entry_file[0].file = '\0';
        int p = 0;

        for (int i = 0; i < index; i++) {

            for (int j = 0; j < lines; j++) {

                if ((arr_uids_denied_indiv[i] == arr_entry[j].uid)) {
                    if (arr_entry[j].action_denied == 1) {
                        arr_entry_file[index2].file = (char * ) malloc(strlen(arr_entry[j].file));

                        strcpy(arr_entry_file[index2].file, arr_entry[j].file);
                        index2++;
                        p++;
                    }
                }
            }

            int length2 = index2;
            int fr2[length2];
            int visited2 = -1;

           for (int i = 0; i < length2; i++) {
                int count2 = 1;
                for (int j = i + 1; j < length2; j++) {
                    if (strcmp(arr_entry_file[i].file, arr_entry_file[j].file) == 0) {
                        count2++;
                        fr2[j] = visited2;
                    }
                }
                if (fr2[i] != visited2)
                    fr2[i] = count2;
            }

            int number_of_modifications = 0;
           for (int k = 0; k < length2; k++) {

                if (fr2[k] != visited2) {
                    number_of_modifications++;
                    num++;
                }
            }

if(number_of_modifications>=7)
{
           printf("\nUid:%d | Number of different action denied files:%d\n", arr_uids_denied_indiv[i], number_of_modifications);
           }

        }
        if (num == 0) {
            printf("There are no action_denied=1 logs any user\n");
        }
        fclose(file);

    } else {
        printf("Log file does not exist in /var/tmp/file_logging.log");
    }

}

void
list_file_modifications(FILE * log, char * file_to_scan) {
    if (access("/var/tmp/file_logging.log", F_OK) == 0) {
        // file exists

        int num = 0;
        int log_size = getFileSize("/var/tmp/file_logging.log");

        FILE * file = fopen("/var/tmp/file_logging.log", "r");

        char * line_array = (char * ) malloc(log_size);
        int line_number = getLineNumber(line_array, log_size, file);

        struct entry arr_entry[line_number / 7];
        int lines = 0;

        if (log_size != 0) {
            returnLogStruct(arr_entry, & lines);
        }

        /***GET ALL UIDS IN THE FILE file_to_scan*******************/
        int k = 0;
        int index_uid = 0;
        int * uids = (int * ) malloc(lines * 4);

        for (int i = 0; i < lines; i++) {

            char * help_file = (char * ) malloc(strlen(arr_entry[i].file));
            strcpy(help_file, arr_entry[i].file);
            int len = strlen(arr_entry[i].file) - strlen(file_to_scan) - 1;
            char help_file2[len];
            help_file2[0] = '\0';

            for (int j = len; j < strlen(arr_entry[i].file); j++) //copy from fullpath only the file to help_file2
            {

                help_file2[k] = help_file[j];
                k++;
                if (k == strlen(file_to_scan)) {
                    k = 0;
                    break;
                }

            }
            help_file2[strlen(file_to_scan)] = '\0';
            if (strcmp(file_to_scan, help_file2) == 0) //get all uids of this file
            {
                uids[index_uid] = arr_entry[i].uid;

                index_uid++;
            }

        }

        /*GET ALL INDIVIUAL USERS IN AN ARRAY*************************************************/
        int length = index_uid;
        index_uid = 0;

        int fr[length];
        int visited = -1;

        for (int i = 0; i < length; i++) {
            int count = 1;
            for (int j = i + 1; j < length; j++) {
                if (uids[i] == uids[j]) {

                    count++;
                    fr[j] = visited;
                }
            }
            if (fr[i] != visited)
                fr[i] = count;
        }
        int * uids_individual = (int * ) malloc(length * 4);
        int l = 0;

        for (int t = 0; t < length; t++) {
            if (fr[t] != visited) {

                uids_individual[l] = uids[t];
                l++;

            }
        }

        int index = 0;
        struct entry_fing2 arr_entry_fing2[lines];

        /*FOR EACH INDIVIDUAL USER CHECK NUMBER OF DIFFERENT FINGERPRINTS*******************/
        for (int i = 0; i < l; i++) {

            for (int j = 0; j < lines; j++) {

                if (uids_individual[i] == arr_entry[j].uid) {

                    char * help_filex = (char * ) malloc(strlen(arr_entry[j].file));
                    strcpy(help_filex, arr_entry[j].file); //copy to help_file the fullpath
                    int lenx = strlen(arr_entry[j].file) - strlen(file_to_scan) - 1;

                    char help_file2x[lenx];
                    help_file2x[0] = '\0';
                    k = 0;
                    for (int n = lenx; n < strlen(arr_entry[i].file); n++) {

                        help_file2x[k] = help_filex[n];

                        k++;
                        if (k == strlen(file_to_scan)) {
                            break;
                        }

                    }
                    help_file2x[strlen(file_to_scan)] = '\0';
                    //  printf("\n%s",help_file2x);
                    if (strcmp(file_to_scan, help_file2x) == 0) {

                        arr_entry_fing2[index].fingerprint = (char * ) malloc(strlen(arr_entry[j].fingerprint));

                        strcpy(arr_entry_fing2[index].fingerprint, arr_entry[j].fingerprint);

                        index++;

                    }

                }

            }

            int length2 = index;

            int fr2[length2];
            int visited2 = -1;

            for (int i = 0; i < length2; i++) {
                int count2 = 1;
                for (int j = i + 1; j < length2; j++) {
                    if (strcmp(arr_entry_fing2[i].fingerprint, arr_entry_fing2[j].fingerprint) == 0) {
                        count2++;

                        fr2[j] = visited2;
                    }
                }
                if (fr2[i] != visited2)
                    fr2[i] = count2;
            }

            int number_of_modifications = 0;

            for (int p = 0; p < length2; p++) {
                if (fr2[p] != visited2) {
                    number_of_modifications++;
                    num++;
                }
                if (p == length2 - 1) {
                    printf("\nuserid:%d |  number  of modifications:%d\n", uids_individual[i], number_of_modifications);

                }

            }

            if (num == 0) {
                printf("\nThere are no file modifications for this file\n");
            }

        }

        fclose(file);
    } else {
        printf("\nLog file does not exist in /var/tmp/file_logging.log");
    }

}

void number_of_files_last_twenty_min(FILE * log, int num_arg) {

    if (access("/var/tmp/file_logging.log", F_OK) == 0) {
        // file exists

        int log_size = getFileSize("/var/tmp/file_logging.log");

        FILE * file = fopen("/var/tmp/file_logging.log", "r");

        char * line_array = (char * ) malloc(log_size);
        int line_number = getLineNumber(line_array, log_size, file);

        fclose(file);

        struct entry arr_entry[line_number / 7];
        int lines = 0;
        if (log_size != 0) {
            returnLogStruct(arr_entry, & lines);
        }

        char * current_time = (char * ) malloc(strlen((char * ) get_current_time()));
        strcpy(current_time, get_current_time());

        char * result = strstr(current_time, ":");
        char * hour_num = (char * ) malloc(sizeof(char) * 2);
        /*********************FIND HOURS ***********************************/

        if ((strlen(current_time) - strlen(result)) == 1) {
            hour_num[0] = current_time[0];
            hour_num[1] = '\0';

        }
        if ((strlen(current_time) - strlen(result)) == 2) {
            hour_num[0] = current_time[0];
            hour_num[1] = current_time[1];
            hour_num[2] = '\0';

        }
        /**************FIND MINUITS******************************************/
        char * s = (char * ) malloc(strlen(current_time));
        strcpy(s, current_time);
        char * final_char = (char * ) malloc(sizeof(char) * 2);
        const char * PATTERN1 = ":";
        const char * PATTERN2 = ":";

        char * target = NULL;
        char * start, * end;

        if (start = strstr(s, PATTERN1)) {
            start += strlen(PATTERN1);
            if (end = strstr(start, PATTERN2)) {
                target = (char * ) malloc(end - start + 1);
                memcpy(target, start, end - start);
                target[end - start] = '\0';
            }
        }

        char * temp = (char * ) malloc(sizeof(target) + sizeof(":"));
        temp[0] = '\0';

        strcat(temp, hour_num);
        strcat(temp, ":");
        strcat(temp, target);
        strcat(temp, ":");
        temp[strlen(temp)] = '\0';
        char * sec = (char * ) malloc(sizeof(current_time) - sizeof(temp));
        sec[0] = '\0';
        strcat(sec, & current_time[strlen(temp)]);
        sec[strlen(sec)] = '\0';
        /**************FIND SECS******************************************/
        int cur_hours = atoi(hour_num);
        int cur_minuites = atoi(target);
        int cur_seconds = atoi(sec);

        //printf("\nCURRENT TIME : %d:%d:%d",cur_hours,cur_minuites,cur_seconds);

        int num_encrypted = 0;

        for (int i = 0; i < lines; i++) {
            if (arr_entry[i].access_type == 0) {
                char * current_time_log = (char * ) malloc(strlen((char * ) arr_entry[i].time));

                strcpy(current_time_log, (char * ) arr_entry[i].time);

                char * result_log = strstr(current_time_log, ":");
                char * hour_num_log = (char * ) malloc(sizeof(char) * 2);
                /*********************FIND HOURS ***********************************/
                //strncpy(hour_num,current_time,strlen(current_time)-strlen(result));
                if ((strlen(current_time_log) - strlen(result_log)) == 1) {
                    hour_num_log[0] = current_time_log[0];
                    hour_num_log[1] = '\0';

                }
                if ((strlen(current_time_log) - strlen(result_log)) == 2) {
                    hour_num_log[0] = current_time_log[0];
                    hour_num_log[1] = current_time_log[1];
                    hour_num_log[2] = '\0';

                }

                /**************FIND MINUITS******************************************/
                char * s_log = (char * ) malloc(strlen(current_time_log));
                strcpy(s_log, current_time_log);
                char * final_char_log = (char * ) malloc(sizeof(char) * 2);
                const char * PATTERN1_log = ":";
                const char * PATTERN2_log = ":";

                char * target_log = NULL;
                char * start_log, * end_log;

                if (start_log = strstr(s_log, PATTERN1_log)) {
                    start_log += strlen(PATTERN1_log);
                    if (end_log = strstr(start_log, PATTERN2_log)) {
                        target_log = (char * ) malloc(end_log - start_log + 1);
                        memcpy(target_log, start_log, end_log - start_log);
                        target_log[end_log - start_log] = '\0';
                    }
                }

                char * temp_log = (char * ) malloc(sizeof(target_log) + sizeof(":"));
                temp_log[0] = '\0';

                strcat(temp_log, hour_num_log);
                strcat(temp_log, ":");
                strcat(temp_log, target_log);
                strcat(temp_log, ":");
                temp_log[strlen(temp_log)] = '\0';
                char * sec_log = (char * ) malloc(sizeof(current_time_log) - sizeof(temp_log));
                sec_log[0] = '\0';
                strcat(sec_log, & current_time_log[strlen(temp_log)]);
                sec[strlen(sec_log)] = '\0';

                int cur_hours_log = atoi(hour_num_log);
                int cur_minuites_log = atoi(target_log);
                int cur_seconds_log = atoi(sec_log);

                //printf("\nLog : %d:%d:%d",cur_hours_log,cur_minuites_log,cur_seconds_log);

                if (cur_hours - cur_hours_log == 0 && arr_entry[i].access_type == 0) {

                    if (cur_minuites - cur_minuites_log <= 20) {
                        num_encrypted++;

                    }
                }

            }

        }

        printf("\nNumber of files created last 20 minuits: %d", num_encrypted);
        if (num_encrypted >= num_arg) {
            printf("\nIndicates suspicious behavior\n");
        } else {
            if (num_encrypted == 0) {
                printf("There are no files created the last 20 minuits");
            }
            printf("\nDoes not indicate suspicious behavior\n");
        }

    } else {
        printf("\nLog file does not exist in /var/tmp/file_logging.log");
    }

}

void print_encrypted_files(FILE * log) {
    if (access("/var/tmp/file_logging.log", F_OK) == 0) {
        // file exists

        int log_size = getFileSize("/var/tmp/file_logging.log");

        FILE * file = fopen("/var/tmp/file_logging.log", "r");

        char * line_array = (char * ) malloc(log_size);
        int line_number = getLineNumber(line_array, log_size, file);

        struct entry arr_entry[line_number / 7];
        int lines = 0;

        if (log_size != 0) {
            returnLogStruct(arr_entry, & lines);
        }
        char * fname;
        char * fname2;
        char * fname3;
        char * help;
        //char files[lines/7][500];
        int count = 0;
        int exists = 0;
        for (int i = 0; i < lines; i++) //for all the logs
        {
            //if file has action type == 0 

            fname = (char * ) malloc(strlen(arr_entry[i].file)); //check if it is not .encrypt

            //strcpy(fname4,fname);
            strcpy(fname, arr_entry[i].file);
            strcpy(fname, & fname[strlen(fname) - strlen(".encrypt") - 1]);
            fname[strlen(fname) - 1] = '\0';

            if (strcmp(fname, ".encrypt") != 0 && arr_entry[i].access_type == 0) {

                for (int j = i; j < lines; j++) {
                    fname2 = (char * ) malloc(strlen(arr_entry[j].file)); //check if it is .encrypt
                    strcpy(fname2, arr_entry[j].file);
                    strcpy(fname2, & fname2[strlen(fname2) - strlen(".encrypt") - 1]);
                    fname2[strlen(fname2) - 1] = '\0';

                    if (strcmp(fname2, ".encrypt") == 0 && arr_entry[j].access_type == 2) {

                        //check if without the .encrypt the fullpath is the same
                        fname3 = (char * ) malloc(strlen(arr_entry[j].file));

                        strcpy(fname3, arr_entry[j].file);
                        fname3[strlen(fname3) - strlen(".encrypt") - 1] = '\0';

                        // printf("\n %ld Fname3: %s - ",strlen(fname3),fname3);
                        // help = (char * )malloc(strlen(arr_entry[i].file));
                        strcpy(fname, arr_entry[i].file);
                        fname[strlen(fname) - 1] = '\0';
                        //printf("\n %ld %s - ",strlen(arr_entry[i].file),arr_entry[i].file);
                        // printf("\n fname: %ld %s - ",strlen(fname),fname);

                        if (strcmp(fname3, fname) == 0) {

                            printf("\n %s", & fname[1]);
                            // strcpy(files[count],fname);

                            count++;
                            break;

                        }

                        free(fname3);

                    }
                    free(fname2);

                    //free(help); 

                }

            }
            free(fname);

        }
        if (count == 0) {
            printf("There are no files that are opened and then encrypted");
        }
    } else {
        printf("\nLog file does not exist in /var/tmp/file_logging.log");
    }

}

int
main(int argc, char * argv[]) {

    int ch;
    FILE * log;

    if (argc < 2)
        usage();

    log = fopen("/var/tmp/file_logging.log", "r");

    if (log == NULL) {
        printf("Error opening log file \"%s\"\n", "./log");
        return 1;
    }

    while ((ch = getopt(argc, argv, "hi:mv:e")) != -1) {
        switch (ch) {
        case 'i':
            list_file_modifications(log, optarg);
            break;
        case 'm':

            list_unauthorized_accesses(log);
            break;
        case 'v':

            number_of_files_last_twenty_min(log, atoi(optarg));
            break;
        case 'e':
            print_encrypted_files(log);
            break;

        default:
            usage();
        }

    }

    fclose(log);
    argc -= optind;
    argv += optind;

    return 0;
}
