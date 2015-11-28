/* Programmed by Kelvin Watson
* File name: otp_enc_d.c 
* Created/Last modified: 24Nov15 / 26Nov15
* Description: Acts as a server, receiving data
* and encoding it to ciphertext
* Sources/Citations: http://beej.us/guide/bgnet/output/html/multipage/advanced.html
*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 

#define FLUSH fflush(stdout);
#define MSG_SIZE 1000

/* Clears buffer after keyboard input via fgets */
void clearBuffer(FILE* fp){
	int c;    
	while ( (c = fgetc(fp)) != EOF && c != '\n');
}

/* Calls send() until all bytes sent */
int sendAll(int s, char *buf, int *len){
    int total = 0;        // bytes sent
    int bytesleft = *len; // bytes left to send
    int n;
	
	while(total < *len) {
        n = send(s, buf+total, bytesleft, 0);
        printf("CLIENT sending chunk n=%dbytes\n",n);
		if (n == -1) { break; }
        total += n;
        bytesleft -= n;
    }
    *len = total; // return number actually sent here
	
    return n==-1?-1:0; // return -1 on failure, 0 on success
} 

/* Calls recv() until all bytes received */
int recvAll(int clientSocket, int size, char* data){
	int bytesLeft = size;
	int totalBytesRecvd =0, n=0;
	//printf("DATA BEFORE READ?=%s",data);
	memset(data,'\0',sizeof(data));
	while (bytesLeft != 0){
		fprintf(stderr, "==CLIENT== reading %d bytes\n", bytesLeft);
		n = recv(clientSocket, data, bytesLeft, 0);
		//printf("DATA AFTER A READ?=%s",data);
		//printf("1. n=%d",n);
		if (n == 0){
			printf("==CLIENT== 2. n=%d\n",n);
			break;
		}
		else if (n < 0 && errno != EINTR){
			printf("==CLIENT== 3. n=%d\n",n);
			fprintf(stderr, "Exit %d\n", __LINE__);
			exit(1);
		}
		else if (n > 0){
			printf("==CLIENT==4. n=%d\n",n);
			totalBytesRecvd += n;
			data += n;
			bytesLeft -= n;
			//printf("4. n=%d, totalBytesRecvd=%d, bytesLeft=%d",n, totalBytesRecvd, bytesLeft);
			//fprintf(stderr, "read %d bytes - remaining = %d\n", n, bytesLeft);
		}
	}
	//fprintf(stderr, "read total of %d bytes, dataRead=%s\n", totalBytesRecvd,data);
	printf("==CLIENT== finished receiving ");FLUSH;
	return n==-1?-1:0; // return -1 on failure, 0 on success
}



int main(int argc, char* argv[]){
	/* Define variables */
	char userInput[MSG_SIZE] = {0}, plaintext[MSG_SIZE] = {0}, key[MSG_SIZE] = {0}, buf[MSG_SIZE] = {0}, data[MSG_SIZE] = {0};
	int i, clientSocket, portno, len, pLen, kLen;
	struct sockaddr_in serverAddress;
	struct hostent *server;
	char *endptr, *inputExists;
	char c;
	
	if(argc != 4){ //incorrect number of arguments
		fprintf(stderr,"Usage: otp_enc plaintext key port\n");
		exit(1);
	}
	
	errno=0;
	portno = strtol(argv[3],&endptr,10);
	if ((errno == ERANGE && (portno == LONG_MAX || portno == LONG_MIN)) || (errno != 0 && portno == 0)) {
		fprintf(stderr,"Error: Invalid port number\n");
		exit(1); 
	} else if (portno<0 || portno>65535) {
		fprintf(stderr,"Error: Invalid port number\n");
		exit(1); 
	} else if(!portno){
		fprintf(stderr,"Error: port number must be an integer\n");
		exit(1);
	}
	printf("TRACE: portno=%d\n",portno); FLUSH;
	
	if((clientSocket = socket(AF_INET,SOCK_STREAM,0))<0){
		perror("otp_enc: socket"); FLUSH;
		exit(1);
	}
	
	if ((server=gethostbyname("localhost"))==NULL) {
		fprintf(stderr,"otp_enc: ERROR, no such host\n");
        exit(1);
	}
	
	/* Set up the server to connect to */
	memset((char*)&serverAddress, '\0', sizeof(serverAddress));
	serverAddress.sin_family = AF_INET;
    memcpy((char *)&serverAddress.sin_addr.s_addr, (char *)server->h_addr, server->h_length); 
	serverAddress.sin_port = htons(portno);
	
	/* Connect to server */
	if(connect(clientSocket,(struct sockaddr*)&serverAddress,sizeof(serverAddress))<0){
		printf("Error: could not contact otp_enc_d on port %d\n",portno);FLUSH;
		exit(2);
	} else{
		printf("otp_enc: CONNECTED TO SERVER"); FLUSH;
	}
	
	/* Send the otp_enc */
	//memset(userInput,0,sizeof(userInput)); //clear the command string
	len=7;
	char identity[]="otp_enc";
	printf("ABOUT TO SEND=%s\n",identity); FLUSH;
	
	/* send identity */
	if(sendAll(clientSocket,identity,&len) == -1){
		fprintf(stderr,"otp_enc: send error\n");
	}
	memset(data,'\0',sizeof(data));
	if(recvAll(clientSocket,2,data) == -1){
		fprintf(stderr,"otp_enc: recv error\n");
		exit(1);
	} else if(strcmp(data,"OK")==0){
		printf("ACK RECVD IS=%s\n",data);FLUSH;
	}
		
	/* Open and read the plaintext file argv[1] and determine length*/
	FILE* fp = fopen(argv[1],"r");
	if(fp == NULL){
		perror("otp_enc: fopen()");FLUSH;
		exit(1);
	}
	fseek(fp,0,SEEK_SET); //rewind to beginning of file
	memset(plaintext,'\0',sizeof(plaintext));
	//memset(buf,'\0',sizeof(buf));
	i=0;
	while ((c = fgetc(fp)) != EOF){
		if(c!=32 && c!=13 && c!=10 && (c<65 || c>90)){
			printf("c=%c\n",c);
			printf("otp_enc error: input contains bad characters\n"); FLUSH;
			exit(1);
		}
		plaintext[i++]=c;
	}
	
	pLen=(int)(strlen(plaintext));
	//printf("\nTRACE:otp_enc: read in data from plaintextfile=%s,len=%d\n",plaintext,pLen); FLUSH; //counts newline
	//printf("i=%d",pLen);
	plaintext[(int)(strlen(plaintext))-1]='\0';
	pLen=(int)(strlen(plaintext));
	//printf("\nTRACE:otp_enc: replace Newline with nullterminator plaintextfile=%s,len=%d\n",plaintext,pLen); FLUSH; //counts newline
	
	/*while(fgets(buf,MSG_SIZE,fp) != NULL){
		strcat(plaintext,buf);
	}*/
	//printf("\nTRACE:otp_enc: read in data from plaintextfile=%s,len=%d\n",plaintext,pLen); FLUSH; //counts newline
	//plaintext[(int)(strlen(plaintext))-1]='\0'; //replace newline with null terminator 
	
	/* Open and read the key file argv[1] and determine length */
	FILE* fpk = fopen(argv[2],"r"); 
	//memset(buf,'\0',sizeof(buf));
	fseek(fpk,0,SEEK_SET);
	//memset(data,'\0',sizeof(data));
	memset(key,'\0',sizeof(key));
	i=0;
	while ((c = fgetc(fpk)) != EOF){
		if(c!=32 && c!=13 && c!=10 && (c<65 || c>90)){
			printf("c=%c\n",c);
			printf("otp_enc error: input contains bad characters\n"); FLUSH;
			exit(1);
		}
		key[i++]=c;
	}
	
	kLen=(int)(strlen(key));
	//printf("\nTRACE:otp_enc: read in data from keyfile=%s,len=%d\n",key,kLen); FLUSH; //counts newline
	//printf("i=%d",kLen);
	key[(int)(strlen(key))-1]='\0';
	kLen=(int)(strlen(key));
	//printf("\nTRACE:otp_enc: replace Newline with nullterminator keyfile=%s,len=%d\n",key,kLen); FLUSH; //counts newline
	
	if(kLen<pLen){
		printf("Error: key '%s' is too short\n",argv[2]); FLUSH;
		exit(1);
	}
	
	
	fclose(fp);
	fclose(fpk);
	
	
	//read the plaintext len into a buffer
	memset(buf,'\0',sizeof(buf));
	sprintf(buf,"%05d",pLen); //pad with leading zeros
	printf("plaintextlen=%s\n",buf); FLUSH;
	int digits = (int)(strlen(buf)); //numDigits == numBytes
	
	
	printf("CLIENT's digits is =%d\n",digits);
	/* pad this with zeroes to total of 5 digits */
	char tmp[5] = {'0'}; //padded with 0's
	printf("CLIENT tmp=%s\n",tmp);FLUSH;
	
	//insert digits from buf into tmp starting at far right
	int j=4;
	for(i=(digits-1); i>=0; i--){
		printf("CLIENT buf[i]==%c",buf[i]);
		tmp[j]=buf[i];
		printf("CLIENT tmp[j]==%c",tmp[j]);
		--j;
	} 
	printf("CLIENT tmp=%s\n",tmp);FLUSH;
	
	
	
	
	/* send length of plaintext */
	len=5;
	if(sendAll(clientSocket,tmp,&len) == -1){
		fprintf(stderr,"otp_enc: send error\n");
	}
	printf("CLIENT JUST FINISHED SENDING PLAINTEXT LEN\n"); FLUSH;
	
	memset(data,'\0',sizeof(data));
	if(recvAll(clientSocket,2,data) == -1){
		fprintf(stderr,"otp_enc: recv error\n");
		exit(1);
	} else if(strcmp(data,"OK")==0){
		printf("ACK RECVD IS=%s\n",data);FLUSH;
	}
	
	printf("CLIENT ABOUT TO SEND PLAINTEXT\n"); FLUSH;
	/* send plaintext */
	len=pLen;
	printf("plaintext=%s",plaintext);
	if(sendAll(clientSocket,plaintext,&len) == -1){
		fprintf(stderr,"otp_enc: send error\n");
	}
	
	//send plaintext data length to otp_enc_d
	//receive acknowledgement from otp_enc_d
	//send plaintext to otp_enc_d
	//recv acknowledgement from otp_enc_d
	
	//open the key file argv[1]
	//read the key file data into a buffer
	//send key data length to otp_enc_d
	//receive acknowledgement from otp_enc_d
	//send key to otp_enc_d
	//recv acknowledgement from otp_enc_d
	
	
	
	return 0;
}
