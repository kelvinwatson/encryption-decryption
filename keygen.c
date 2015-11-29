/* Programmed by Kelvin Watson
* File name: keygen.c 
* Created/Last modified: 24Nov15 / 27Nov15
* Description: Generates a key 
* Usage: keygen keylength or keygen keylength > file
* Sources/Citations: http://beej.us/guide/bgnet/output/html/multipage/advanced.html
*/

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <time.h>

#define FLUSH fflush(stdout)
#define KEY_LEN 999999

int main(int argc, char* argv[]){
	srand(time(NULL));
	int	i, kLen;
	char *endptr;

	/* validate command line arguments */
	if((argc !=2 && argc != 4)){ //incorrect number of arguments
		fprintf(stderr,"Usage: keygen keylength   or \n");
		fprintf(stderr,"Usage: keygen keylength > fileName\n");
		exit(1);
	}
	/* generate string of len */
	
	/* validate and convert string representation of keylength to int */
	errno=0;
	kLen = strtol(argv[1],&endptr,10);
	if ((errno == ERANGE && (kLen == LONG_MAX || kLen == LONG_MIN)) || (errno != 0 && kLen == 0)) {
        perror("strtol"); FLUSH;
        exit(1); 
    } else if(!kLen){
		fprintf(stderr,"Error: keylength must be an integer\n");
        exit(1);
	}

	/* populate buffer with random sequence of chars */
	char key[KEY_LEN] = {0};
	char legalChars[27] = {-1};
	legalChars[26]=32;
	for(i=0; i<26; i++){
		legalChars[i]=i+65;
	}
	for(i=0; i<kLen; i++){
		key[i]=legalChars[rand()%27];
	}
	printf("%s\n",key); FLUSH;	
	return 0;
}