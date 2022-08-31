#include <stdio.h>

#include <string.h>

#include <stdlib.h>

int main(int argc, char * argv[]) {
    int i;
    size_t bytes;
    FILE * file_original;
    int total_num = atoi(argv[1]);
    char filenames[total_num][20];
    memset(filenames, 0, total_num * 10 * sizeof(char));

    for (int k = 0; k < total_num; k++) {
        char str[10] = "";
        sprintf(str, "%d", k);

        //strcpy(filenames[k],"/");
        strcpy(filenames[k], argv[2]);
        strcat(filenames[k], "/");
        strcat(filenames[k], "file_");
        strncat(filenames[k], str, strlen(str));

    }
    for (i = 0; i < total_num; i++) {

        file_original = fopen(filenames[i], "w");

        if (file_original == NULL)
            printf("fopen error\n");
        else {

            bytes = fwrite(filenames[i], 1, strlen(filenames[i]), file_original);
            fclose(file_original);
        }
    }

}
