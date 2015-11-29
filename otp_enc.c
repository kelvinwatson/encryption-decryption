/* Programmed by Kelvin Watson
* File name: otp_enc.c 
* Created/Last modified: 24Nov15 / 27Nov15
* Description: Acts as a client, sending plaintext and a key to a server,
* then receiving and outputting the encoded ciphertext
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
#define MSG_SIZE 999999
	

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
		if (n == -1) { break; }
        total += n;
        bytesleft -= n;
    }
    *len = total; // return number actually sent here
	
    return n==-1?-1:0; // return -1 on failure, 0 on success
} 

void sendData(int clientSocket, char* data, int length){
	int len=length;
	if(sendAll(clientSocket,data,&len) == -1){
		fprintf(stderr,"otp_enc: send error\n");
	}
	memset(data,'\0',sizeof(data));
}

/* Calls recv() until all bytes received */
int recvAll(int clientSocket, int size, char* data){
	int bytesLeft = size;
	int totalBytesRecvd =0, n=0;
	memset(data,'\0',sizeof(data));
	while (bytesLeft != 0){
		n = recv(clientSocket, data, bytesLeft,0);
		if (n < 0 && errno != EINTR){
			perror("otp_enc: recv()"); FLUSH;
			exit(1);
		}
		else if (n > 0){
			totalBytesRecvd += n;
			data += n;
			bytesLeft -= n;
		}
	}
	return n==-1?-1:0; // return -1 on failure, 0 on success
}


void receiveData(int clientSocket, int size, char* data){
	memset(data,'\0',sizeof(data));
	if(recvAll(clientSocket,size,data) == -1){
		fprintf(stderr,"otp_enc: recv error\n");
	}
}

int readFile(char* file, char* buf){
	int i;
	char c;
	FILE* fp = fopen(file,"r");
	if(fp == NULL){
		perror(file);FLUSH;
		exit(1);
	}
	fseek(fp,0,SEEK_SET); //rewind to beginning of file
	memset(buf,'\0',sizeof(buf));
	i=0;
	while ((c = fgetc(fp)) != EOF){
		if(c!=32 && c!=13 && c!=10 && (c<65 || c>90)){
			fprintf(stderr,"otp_dec error: input file %s contains bad characters\n",file); FLUSH;
			exit(1);
		}
		buf[i++]=c;
	}
	fclose(fp);
	buf[(int)(strlen(buf))-1]='\0';
	return (int)(strlen(buf));;
}


void padWithLeadingZeros(int len,char* tmp){
	char buf[MSG_SIZE] = {0};
	sprintf(buf,"%05d",len); //pad w/ leading 0's and convert to str
	int digits = (int)(strlen(buf)); //numDigits == numBytes
	/* pad this with zeroes to total of 5 digits */
	memset(tmp,'\0',sizeof(tmp));
	/* insert digits from buf into tmp starting at far right */
	int i, j=4;
	for(i=(digits-1); i>=0; i--){
		tmp[j]=buf[i];
		--j;
	} 
}

int main(int argc, char* argv[]){
	/* Define variables */

	char plaintext[MSG_SIZE] = {0}, key[MSG_SIZE] = {0}, data[MSG_SIZE] = {0};
	int clientSocket, portno, pLen, kLen;
	struct sockaddr_in serverAddress;
	struct hostent *server;
	char *endptr;
	char acknowledgement[] = "OK";
	char tmp[5] = {'0'};
		
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
	}
	
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
		fprintf(stderr,"Error: could not contact otp_enc_d on port %d\n",portno);FLUSH;
		exit(2);
	}
	char identity[]="otp_enc";	
	
	//printf("CLIENT: send#1\n");
	sendData(clientSocket,identity,7); /* Send identity */
	
	//printf("CLIENT: receive#1\n");
	receiveData(clientSocket,2,data);		
	if(strcmp(data,"NO")==0){ /* Rejected due to incorrect identity */
		//printf("Received a no!");
		close(clientSocket);
		exit(1);
	}

	pLen = readFile(argv[1],plaintext);/* Open, read plaintext file, compute length*/	
	//printf("CLIENT pLen=%d",pLen);
	kLen = readFile(argv[2],key); /* Open, read key and compute length */
	if(kLen<pLen){
		printf("Error: key '%s' is too short\n",argv[2]); FLUSH;
		exit(1);
	}
	
	padWithLeadingZeros(pLen,tmp); 	/* Read the plaintext len into a buffer */
	//printf("CLIENT after padding, we get tmp=%s\n",tmp);
	//printf("CLIENT: send#2\n");
	sendData(clientSocket,tmp,5);
	
	//printf("CLIENT: receive#2\n");
	receiveData(clientSocket,2,data); /* Receive acknowledgement */
	
	//printf("CLIENT: send#3\n");
	sendData(clientSocket,plaintext,pLen); /* Send plaintext */

	//printf("CLIENT: receive#3\n");
	receiveData(clientSocket,2,data); /* Receive acknowledgement */
	padWithLeadingZeros(kLen,tmp); /* Read the key len into a buffer*/
	
	//printf("CLIENT: send#4\n");
	sendData(clientSocket,tmp,5); /* Send length of keyfile */

	//printf("CLIENT: receive#4\n");
	receiveData(clientSocket,2,data); /* Receive acknowledgement */

	//printf("CLIENT: send#5\n");
	sendData(clientSocket,key,kLen); /* Send key */

	//printf("CLIENT: receive#5\n");
	receiveData(clientSocket,2,data); /* Receive acknowledgement */
	
	//printf("CLIENT: send#6\n");
	sendData(clientSocket,acknowledgement,2); /* Send acknowledgement */
	memset(data,'\0',sizeof(data));

	//printf("CLIENT: receiving CIPHERTEXT from SERVER, pLen=%d\n",pLen);
	receiveData(clientSocket,pLen,data); /* Receive ciphertext */
	printf("%s\n",data); //STDOUT the ciphertext
	
	//printf("CLIENT: sending last ACK to SERVER\n");
	sendData(clientSocket,acknowledgement,2); /* Send acknowledgement */
	
	//printf("CLIENT: receiving last ACK from SERVER\n");
	receiveData(clientSocket,2,data); /* Receive acknowledgement */
	//printf("CLIENT GOT data=%s",data);
	//printf("CLIENT: closing socket\n");
	if(close(clientSocket)<0){
		perror("close"); FLUSH;
	}
	
	return 0;
}
