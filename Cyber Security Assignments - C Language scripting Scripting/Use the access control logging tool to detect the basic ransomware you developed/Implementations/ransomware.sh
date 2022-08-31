#!/bin/bash


#usage(){echo "Usage: [-x | number of files to create][-d | directory name]"}

menu () {
        echo -ne "
Menu
-------------------------------------------------
1) Create a volume of files 
2) Encrypt  a number files in a specified directory 
3) Decrypt a number files in a specified directory 
4)Create a volume of files and encrypt them in a single command
To exit press any other key
-------------------------------------------------
Choose an option:"

        read a 
        case $a in 
        1) create_files;menu;;
         2) encrypt;menu;;
         3) decrypt;menu;;
         4) create_files_encrypt;menu;;
        *)echo
        esac
}

function create_files(){
        
echo "Directory name to create files:"
read dir
        
echo -n "Number of files to create:"
read fnum



echo Creating ${fnum} files in directory names ${dir}       
{      #If directory exists delete it and create it again
if [ -d ${dir} ];
then
rm -rf ${dir}
fi


if [ ! -d ${dir} ] 
then
mkdir ${dir}
fi



LD_PRELOAD=./logger.so ./test_aclog ${fnum} ${dir}
} &> /dev/null
echo Files created!     
}

function encrypt(){
   
echo "Directory name:"
read dir

ls -l ${dir}
     

echo -n "Number of files to encrypt:"
read fnum
echo Encrypting ${fnum} files in directory named ${dir}..
{
let val=${fnum}-1
for i in $(seq 0 $val);
do array[$i]="file_$i";
done; 
for i in $(seq 0 $val);
do
echo "encrypt"
LD_PRELOAD=$PWD/logger.so openssl enc -aes-256-ecb -in ${dir}/${array[$i]} -out ${dir}/${array[$i]}.encrypt -k 1234;
done;

for i in $(seq 0 $val);
do
rm ${dir}/${array[$i]}
done;
} &> /dev/null
echo Original files deleted.
echo Files encrypted successefully !  


       
}

function decrypt(){
   
echo "Directory name:"
read dir

ls -l ${dir}
     

echo -n "Number of files to decrypt:"
read fnum

echo Decrypting ${fnum} files in directory named ${dir}..
{
let val=${fnum}-1


for i in $(seq 0 $val);
do array[$i]="file_$i";
done; 

for i in $(seq 0 $val);
do
echo 

LD_PRELOAD=$PWD/logger.so openssl aes-256-ecb -in ${dir}/${array[$i]}.encrypt -out ${dir}/${array[$i]} -d -k 1234
done;
} &> /dev/null
echo Files decrypted successefully !  



       
}
function create_files_encrypt(){
  
echo "Directory name to create files:"
read dir
        
echo -n "Number of files to create:"
read fnum




        
#If directory exists delete it and create it again
if [ -d ${dir} ];
then
rm -rf ${dir}
fi

#DIRECTORY=$1

if [ ! -d ${dir} ] 
then
mkdir ${dir}
fi


#directory

echo Encrypting ${fnum} files in directory named ${dir}..
{
LD_PRELOAD=./logger.so ./test_aclog ${fnum} ${dir}


let val=${fnum}-1


for i in $(seq 0 $val);
do array[$i]="file_$i";
done; 




for i in $(seq 0 $val);
do
echo "encrypt"
LD_PRELOAD=$PWD/logger.so openssl enc -aes-256-ecb -in ${dir}/${array[$i]} -out ${dir}/${array[$i]}.encrypt -k 1234;
done;

for i in $(seq 0 $val);
do
rm ${dir}/${array[$i]}
done;
} &> /dev/null
echo Original files deleted.
echo Files encrypted successefully !  


           
}


make
menu


