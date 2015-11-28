/* Programmed by Kelvin Watson
* File name: otp_enc_d.c 
* Created/Last modified: 24Nov15 / 26Nov15
* Description: Acts as a server, receiving data
* and encoding it to ciphertext
* Sources/Citations: http://beej.us/guide/bgnet/output/html/singlepage/bgnet.html#socket
* http://beej.us/guide/bgnet/output/html/multipage/advanced.html
* http://www.linuxhowtos.org/data/6/server2.c 
* http://stackoverflow.com/questions/8470403/socket-recv-hang-on-large-message-with-msg-waitall
*/

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>

#define FLUSH fflush(stdout)
#define MSG_SIZE 1000

/* Encodes message to ciphertext based on key */
void encode(char* msg, char* key, int len){
	int i,k,m,r;	
	for(i=0; i<len; i++){
		/* Reduce each letter's ASCII representation to int from 0-26 for manipulation*/
		m=(int)msg[i]; 
		k=(int)key[i];
		m = (m==32)? 26 : (m-65);
		k = (k==32)? 26 : (k-65);
		/* Add int representations, then mod 27, then convert back to ASCII */
		r=(m+k)%27;
		r = (r==26)? 32 : (r+65);
		msg[i]=(char)r;
	}
}

/* Handles SIGCHLD signals */
void sigchld_handler(int s){
	//printf("SIGCHLD HANDLER\n");
	int saved_errno = errno;
	while(waitpid(-1, NULL, WNOHANG) > 0);
	errno = saved_errno;
}

/* Calls recv() until all bytes received */
int recvAll(int clientSocket, int size, char* data){
	int bytesLeft = size;
	int totalBytesRecvd =0, n=0;
	
	while (bytesLeft != 0){
		n = recv(clientSocket, data, bytesLeft, 0);
		if (n == 0) break;
		else if (n < 0 && errno != EINTR) exit(1);
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
		fprintf(stderr,"otp_enc_d: recv error\n");
	} //printf("1. TRACE: data=%s\n",data); FLUSH;
}

void sendData(int clientSocket, char* data, int length){
	int len=length;
	if(sendAll(clientSocket,data,&len) == -1){
		fprintf(stderr,"otp_enc: send error\n");
	}
	
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

void removeLeadingZeroes(char* data){
	char tmp[5]={0};
	int i=0, j=0;
	for(i=0; i<((int)(strlen(data))); i++){
		if(data[i] != '0'){
			tmp[j++]=data[i];
		}
	}
	memset((char*)data,'\0',sizeof(data));
	strcpy(data,tmp);//printf("SERVER tmp=%s\n",tmp); FLUSH;
}

int convertStringToInteger(char* data){
	errno=0;
	char *endptr;
	int len = strtol(data,&endptr,10);
	if ((errno == ERANGE && (len == LONG_MAX || len == LONG_MIN)) || (errno != 0 && len == 0)) {
		fprintf(stderr,"Error: Invalid plaintext length\n");
		exit(1); 
	} else if(!len){
		fprintf(stderr,"Error: Plaintext's length must be an integer\n");
		exit(1);
	}
	return len;
}

int main(int argc, char* argv[]){
	/* Define variables*/
	int ackLen, serverSocket, clientSocket, portno, result, len, numClientsConnected=0;
	pid_t pid;
	socklen_t clientLen;
	struct sockaddr_in serverAddress, clientAddress;
	char data[MSG_SIZE]={0}, plaintext[MSG_SIZE]={0}, key[MSG_SIZE]={0};
	char acknowledgement[] = "OK";
	char *endptr;
	struct sigaction sa;
	
	/* Validate command-line arguments (usage) */
	if(argc !=2){
		fprintf(stderr,"Usage: otp_enc_d listening_port\n");
		exit(1);
	}
	
	if((serverSocket = socket(AF_INET,SOCK_STREAM,0))<0){
		perror("otp_enc_d socket");
		exit(1);
	}
	
	memset((char*)&serverAddress, '\0', sizeof(serverAddress));
	
	/* Validate port number */
	errno=0;
	portno = strtol(argv[1],&endptr,10);
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
	
	/* Set up server address */
	serverAddress.sin_family = AF_INET;
	serverAddress.sin_addr.s_addr = INADDR_ANY;
	serverAddress.sin_port = htons(portno);

	/* Bind socket to port */
	if(bind(serverSocket,(struct sockaddr*)&serverAddress,sizeof(serverAddress))<0){
		//close(serverSocket)
		perror("otp_enc_d: bind"); FLUSH;
		exit(1);
	}
	
	/* Listen for connection requests */
	if(listen(serverSocket,5)<0){
		perror("otp_enc_d: listen"); FLUSH;
	}
	clientLen=sizeof(clientAddress);
	
	/* Set up signal handler for SIGCHLD signals */
	sa.sa_handler=sigchld_handler; // reap all dead processes
	sigemptyset(&sa.sa_mask);
	sa.sa_flags=SA_RESTART;
	if (sigaction(SIGCHLD,&sa,NULL)==-1) {
		perror("sigaction");
		exit(1);
	}
	/* Accept simultaneous connections */
	while(1){ //accept loop
		if((clientSocket=accept(serverSocket,(struct sockaddr*)&clientAddress,&clientLen))<0){
			perror("otp_enc_d: accept"); FLUSH;
			continue;
		}
		FLUSH;
		pid=fork();
		if(pid<0){ //fork failure
			perror("otp_enc_d: fork failed"); FLUSH;
		}
		if(pid==0){ //child
			close(serverSocket); //child does not need listener
			receiveData(clientSocket,7,data); /* Recv all bytes of authentication, expect 7 bytes/chars in otp_enc*/
			/* Authentication (verify that client is otp_enc) */
			if(strcmp(data,"otp_enc") != 0){ //not the correct identity
				printf("Client %s: connection denied. Client must be otp_enc",data); FLUSH;
				close(clientSocket);
				exit(1);
			} else{ //client identity confirmed
				sendData(clientSocket,acknowledgement,2); /* Send acknowledgement */
				receiveData(clientSocket,5,data); /* Receive length of plaintext for encryption */
				removeLeadingZeroes(data); /* Strip leading zeros before conversion */
				len = convertStringToInteger(data);				
				sendData(clientSocket,acknowledgement,2); /* Send acknowledgement */
				receiveData(clientSocket,len,data);
				strcpy(plaintext,data);
				sendData(clientSocket,acknowledgement,2);
				receiveData(clientSocket,5,data); /* Receive length of keyfile for encryption */				
				removeLeadingZeroes(data); /* Strip leading zeros before conversion */
				len = convertStringToInteger(data);
				sendData(clientSocket,acknowledgement,2);
				receiveData(clientSocket,len,data);
				strcpy(key,data); /* Store key */
				sendData(clientSocket,acknowledgement,2); /* Send acknowledgement */
				encode(plaintext,key,(int)(strlen(plaintext))); /* Perform encryption */
				sendData(clientSocket,plaintext,(int)(strlen(plaintext))); /* Send ciphertext to client */
				receiveData(clientSocket,2,data); /* Receive acknowledgement */
				exit(0); //this child should send SIGCHLD to parent
			}
		}
		else{ //parent
			close(clientSocket);
			numClientsConnected++;
		}
		
	}
	
	return 0;
}