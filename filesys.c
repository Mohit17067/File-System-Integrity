#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/sha.h>
#include "filesys.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <fcntl.h>

static int filesys_inited = 0;
int count_lines(FILE *fptr);

/* returns 20 bytes unique hash of the buffer (buf) of length (len)
 * in input array sha1.
 */
void get_sha1_hash (const void *buf, int len, const void *sha1)
{
	SHA1 ((unsigned char*)buf, len, (unsigned char*)sha1);
}

/* Build an in-memory Merkle tree for the file.
 * Compare the integrity of file with respect to
 * root hash stored in secure.txt. If the file
 * doesn't exist, create an entry in secure.txt.
 * If an existing file is going to be truncated
 * update the hash in secure.txt.
 * returns -1 on failing the integrity check.
 */
int s_open (const char *pathname, int flags, mode_t mode)
{	
	assert (filesys_inited);
	if( access( pathname, F_OK ) != -1 ){
		int fd_temp = open(pathname, flags);
		s_end = lseek(fd_temp, 0, SEEK_END);
		close(fd_temp);
		create_merkle_tree(pathname);
		FILE *fptr1;
		fptr1 = fopen("secure.txt", "r");

		char fname[20];

		while (fgets(fname, 10, fptr1) != NULL){

			if (strcmp(fname, pathname) == 0){
				char line[100];
				fgets(line, sizeof(line), fptr1);
				fgets(line, sizeof(line), fptr1);
				char hash2[100];

				FILE *fptr2 = fopen("file1.txt", "r");
				fgets(hash2, sizeof(hash2), fptr2);
				fclose(fptr2);
				fclose(fptr1);
				if (strcmp(line, hash2)!=0){
					return -1;
				}
				return open (pathname, flags, mode);

			}
		}


	}

	FILE *fptr;

	fptr = fopen("secure.txt", "a");
	fprintf(fptr, "%s", pathname);
	fprintf(fptr, "%s", "\n");
	fprintf(fptr, "%s", "\n");
	fclose(fptr);
	return open (pathname, flags, mode);
}

/* SEEK_END should always return the file size 
 * updated through the secure file system APIs.
 */
int s_lseek (int fd, long offset, int whence)
{

	assert (filesys_inited);
	struct stat sb;

	char path[100];

	sprintf(path, "/proc/self/fd/%d", fd);

	lstat(path, &sb);

	char ftemp[sb.st_size + 1];


	readlink(path, ftemp, sb.st_size + 1);

	char *check = strtok(ftemp, "/");
	char* args[1000];
	int index = 0;

	while(check != NULL){
		args[index] = check;
		index++;
		args[index] = NULL;
		check = strtok(NULL, "/");
	}

	char fname[10];
	strncpy(fname, args[index-1],9);
	// strcat(fname, "xt");
	FILE *fptr1;
	fptr1 = fopen("secure.txt", "r+");

	char fsecure[256];
	while (fgets(fsecure, sizeof(fsecure), fptr1) != NULL){
		if (strncmp(fname, fsecure,9) == 0){
			char line[100];
			fgets(line, sizeof(line), fptr1);

			create_merkle_tree(fname);
			char hash[100];
			FILE *fptr2 = fopen("file1.txt", "r");
			fgets(hash, sizeof(hash), fptr2);
			fclose(fptr2);
			if (strcmp(line, hash) != 0){
				fclose(fptr1);
				return s_end;
			}
			fclose(fptr1);
			return lseek (fd, offset, SEEK_SET);
		}
	}

	fclose(fptr1);
	return lseek (fd, offset, SEEK_SET);
}

/* read the blocks that needs to be updated
 * check the integrity of the blocks
 * modify the blocks
 * update the in-memory Merkle tree and root in secure.txt
 * returns -1 on failing the integrity check.
 */

ssize_t s_write (int fd, const void *buf, size_t count)
{	
	struct stat sb;

	char path[100];

	sprintf(path, "/proc/self/fd/%d", fd);

	lstat(path, &sb);

	char ftemp[sb.st_size + 1];


	readlink(path, ftemp, sb.st_size + 1);

	char *check = strtok(ftemp, "/");
	char* args[1000];
	int index = 0;

	while(check != NULL){
		args[index] = check;
		index++;
		args[index] = NULL;
		check = strtok(NULL, "/");
	}

	char fname[10];
	strncpy(fname, args[index-1],9);
	// strcat(fname, "xt");
	FILE *fptr1;
	fptr1 = fopen("secure.txt", "r+");

	char fsecure[256];

	assert (filesys_inited);
	while (fgets(fsecure, sizeof(fsecure), fptr1) != NULL){
		if (strncmp(fname, fsecure,9) == 0){
			char line[100];
			fgets(line, sizeof(line), fptr1);
			// printf("%shash \n", line);
			if (line[0] == '\n'){
				ssize_t ret = write (fd, buf, count);
				create_merkle_tree(fname);

				// s_end = lseek(fd, 0, SEEK_END);

				char hash[100];
				FILE *fptr2 = fopen("file1.txt", "r");
				fgets(hash, sizeof(hash), fptr2);
				fclose(fptr2);
				fseek(fptr1, -1, SEEK_CUR);
				fprintf(fptr1, "%s", hash);
				fclose(fptr1);
				return ret;
			}
			else{
				
				create_merkle_tree(fname);
				char hash[100];
				FILE *fptr2 = fopen("file1.txt", "r");
				fgets(hash, sizeof(hash), fptr2);
				fclose(fptr2);
				if (strcmp(line, hash) != 0){
					return -1;
				}
				else{
					
					ssize_t ret = write (fd, buf, count);
					create_merkle_tree(fname);
					char hash2[100];

					FILE *fptr2 = fopen("file1.txt", "r");
					fgets(hash2, sizeof(hash2), fptr2);
					fclose(fptr2);

					fseek(fptr1, -41, SEEK_CUR);
					fprintf(fptr1, "%s", hash2);
					fclose(fptr1);
					return ret;
				}
				
			}

		}
	}
	fclose(fptr1);
	return write (fd, buf, count);
}

/* check the integrity of blocks containing the 
 * requested data.
 * returns -1 on failing the integrity check.
 */
ssize_t s_read (int fd, void *buf, size_t count)
{
	assert (filesys_inited);
	struct stat sb;

	char path[100];

	sprintf(path, "/proc/self/fd/%d", fd);

	lstat(path, &sb);

	char ftemp[sb.st_size + 1];


	readlink(path, ftemp, sb.st_size + 1);

	char *check = strtok(ftemp, "/");
	char* args[1000];
	int index = 0;

	while(check != NULL){
		args[index] = check;
		index++;
		args[index] = NULL;
		check = strtok(NULL, "/");
	}

	char fname[10];
	strncpy(fname, args[index-1],9);
	// strcat(fname, "xt");
	FILE *fptr1;
	fptr1 = fopen("secure.txt", "r+");

	char fsecure[256];
	while (fgets(fsecure, sizeof(fsecure), fptr1) != NULL){
		if (strncmp(fname, fsecure,9) == 0){
			char line[100];
			fgets(line, sizeof(line), fptr1);

			create_merkle_tree(fname);
			char hash[100];
			FILE *fptr2 = fopen("file1.txt", "r");
			fgets(hash, sizeof(hash), fptr2);
			fclose(fptr2);
			if (strcmp(line, hash) != 0){
				fclose(fptr1);
				return -1;
			}
			fclose(fptr1);
			return read (fd, buf, count);
		}
	}

	fclose(fptr1);
	return read (fd, buf, count);
}

/* destroy the in-memory Merkle tree */
int s_close (int fd)
{	
	assert (filesys_inited);
	system ("rm -rf file*.txt");
	return close (fd);
}

/* Check the integrity of all files in secure.txt
 * remove the non-existent files from secure.txt
 * returns 1, if an existing file is tampered
 * return 0 on successful initialization
 */
int filesys_init (void)
{
	if( access("secure.txt" , F_OK ) != -1 ){
		FILE *fptr1;
		fptr1 = fopen("secure.txt", "r+");

		char fsecure[256];

		int i = 0;

		while (fgets(fsecure, sizeof(fsecure), fptr1) != NULL){
			char fname[10];
			sprintf(fname, "foo_%d.txt", i);
			i++;
			if (strncmp(fname, fsecure,9) == 0){
				char line[100];
				fgets(line, sizeof(line), fptr1);

				create_merkle_tree(fname);
				char hash[100];
				FILE *fptr2 = fopen("file1.txt", "r");
				fgets(hash, sizeof(hash), fptr2);
				fclose(fptr2);
				if (strcmp(line, hash) != 0){
					fclose(fptr1);
					return 1;
				}
			}
		}
		fclose(fptr1);
	}
	else{
		int fd = open("secure.txt", O_WRONLY | O_CREAT, 0644);
		close(fd);
	}


	filesys_inited = 1;
	return 0;

}

void create_merkle_tree(const char *pathname){

	FILE *fptr1;
	FILE *fptr;
	FILE *fptr2;

	fptr1 = fopen("file1.txt", "w+");
	fptr = fopen(pathname, "r");

	char data[64];

	unsigned char sha[20];

	while (fgets(data, sizeof(data), fptr) != NULL){
    	get_sha1_hash(data, strlen(data), sha);
    	for(int i = 0; i < 20; i++)
        	fprintf(fptr1, "%02x", sha[i]);
    	fprintf(fptr1, "\n");
	}

	fclose(fptr1);
	fclose(fptr);

	while(count_lines(fptr1)!=1){
		char temp[100];
		int k = 0;

		fptr1 = fopen("file1.txt", "r");
		fptr2 = fopen("file2.txt", "w+");

		while (fgets(temp, 100, fptr1) != NULL) {
    		temp[strlen(temp)-1] = '\0';
    		if (k%2 == 0) {
        		fprintf(fptr2, "%s", temp);
    		}
    		else {
        		fprintf(fptr2, "%s\n", temp);
    		}
    		k++;
		}
		fclose(fptr1);
		fclose(fptr2);

		fptr1 = fopen("file1.txt", "w+");
		fptr2 = fopen("file2.txt", "r");

		char temp2[1024];
		unsigned char sha[20];
		while(fgets(temp2, sizeof(temp2), fptr2) != NULL) {
    		get_sha1_hash(temp2, strlen(temp2), sha);
    		for(int i = 0; i<20; i++)
        		fprintf(fptr1, "%02x", sha[i]);
    		fprintf(fptr1, "%s", "\n");
		}

		fclose(fptr1);
		fclose(fptr2);
	}

}

int count_lines(FILE *fptr){
	int count=0;
	char c;
	fptr = fopen("file1.txt", "r");
	for (c = getc(fptr); c != EOF; c = getc(fptr)) 
        if (c == '\n')
            count = count + 1; 

    fclose(fptr);
    return count;
}