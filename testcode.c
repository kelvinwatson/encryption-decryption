#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <string.h>

/* Encodes plaintext to ciphertext based on key */
void encode(char* msg, char* key, int len){
	int i,k,m,r;	
	for(i=0; i<len; i++){
		m=(int)msg[i]; // Reduce letter from ASCII int to 0-26 for manipulation*/
		k=(int)key[i];
		m = (m==32)? 26 : (m-65);
		k = (k==32)? 26 : (k-65);
		r=(m+k)%27; // Add int representations, mod 27, then convert back to ASCII */
		r=(r<0)?r+27:r; //correction to achieve modulo for negative numbers;
		r = (r==26)? 32 : (r+65);
		msg[i]=(char)r;
	}
}

/* Decode ciphertext to plaintext  based on key */
void decode(char* msg, char* key, int len){
	printf("decoding msg=%s!\n",msg);fflush(stdout);
	int i,k,m,r;	
	for(i=0; i<len; i++){
		m=(int)msg[i]; // Reduce ASCII letter to int for manipulation*/
		k=(int)key[i]; 
		m = (m==32)? 26 : (m-65); //reduce ASCII letter to int between 0-26
		k = (k==32)? 26 : (k-65);
		r=(m-k)%27; // Add int representations, then mod 27, then convert back to ASCII */
		r=(r<0)?r+27:r; //correction to achieve modulo for negative numbers;
		r = (r==26)? 32 : (r+65);
		msg[i]=(char)r;
	}
}


int main(){
	char msg[] = "THE RED GOOSE FLIES AT MIDNIGHT";
	char key[] = "MEVMF MTOPWBUCNMXB QMX JCDCXRQGSVQT FVSTJNJCQWOBYCSJ ";
	encode(msg,key,(int)(strlen(msg)));
	printf("ciphertext msg=%s,key=%s\n",msg,key); fflush(stdout);
	decode(msg,key,(int)(strlen(msg)));
	printf("\ndecoded msg=%s",msg); fflush(stdout);
	
	return 0;
}