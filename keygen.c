#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <string.h>


#define FLUSH fflush(stdout)

int main(int argc, char* argv[]){
	srand(time(NULL));
	int	i, r, fdo, kLen;
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
	char key[10000] = {0};
	char legalChars[27] = {-1};
	legalChars[26]=32;
	for(i=0; i<26; i++){
		legalChars[i]=i+65;
	}
	for(i=0; i<27; i++)
		printf("legalChars=%c",legalChars[i]);
	
	for(i=0; i<kLen; i++){
		key[i]=legalChars[rand()%27];
	}
	printf("%s\n",key); FLUSH;	
	return 0;
}