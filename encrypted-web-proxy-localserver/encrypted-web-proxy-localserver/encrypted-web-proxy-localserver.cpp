// encrypted-web-proxy-localserver.cpp : 定义控制台应用程序的入口点。
//

/*
* encrypted-web-server-localserver.cpp
*		This file listens to the requests at some port, encrypts the requests with ssl algorithms and forwards them to remote server.
*		Local server implemented on Windows, while remote on Linux.
*
*	Youyou Lu (luyouyou87@gmail.com)
*	2010/06/01
* TEST: GET / HTTP/1.1
*		host: www.baidu.com
*/
#include "stdafx.h"
#include <winsock2.h>
#include <windows.h>
#pragma comment(lib, "WS2_32")
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/md5.h>
#include <openssl/evp.h>
#pragma comment( lib, "libeay32.lib")

#define SECURE

//#define MD5

#define REMOTESERVER "10.0.1.33" //202.112.50.94
#define LOCALPORT 6000
//#define REMOTEPORT 6002 //not used now

#define TYPE_NORMAL 1
#define TYPE_WRONG 2

#define AUTHEN_RSA 1
#define AUTHEN_MD5 2

void init_socket()
{
	WSADATA wsa_data;
	WORD sockVersion = MAKEWORD(2, 2);
	if(::WSAStartup(sockVersion, &wsa_data) != 0)
	{
		exit(0);
	}
}

SOCKET create_listen_socket()
{
	SOCKET sockfd;
	struct sockaddr_in sin;

	//create
	if((sockfd=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET)
	{
		printf("***create_listen_socket(): socket create error!\n");
		WSACleanup();
		exit(1);
	}

	//bind
	sin.sin_family = AF_INET;
	sin.sin_port = htons(LOCALPORT);
	sin.sin_addr.S_un.S_addr = htonl(INADDR_ANY);
	
	if(bind(sockfd, (struct sockaddr*)&sin, sizeof(struct sockaddr)) == SOCKET_ERROR)
	{
		//int err = WSAGetLastError();
		printf("***create_listen_socket(): socket bind error!\n");
		closesocket(sockfd);
		exit(1);
	}

	//listen
	if(listen(sockfd, 1) == SOCKET_ERROR)
	{
		printf("***create_listen_socket(): socket listen error!\n");
		closesocket(sockfd);
		exit(1);
	}

	return sockfd;
}

char* sub_str_find(char *s, char *d)
{
//printf("********enter %s \n", __func__);
	int lend=strlen(d);
	int lens=strlen(s);
	//printf("%d %d\n", lend, lens);
	if(lend>lens)
		return NULL;
	char *p = s;
	while(1)
	{
		p=strchr(p,d[0]);
//		printf("%c, %s\n", d[0], p);
		if(p==NULL)
			return NULL;
		if(p+lend > s+lens)
		{
//			printf("********leave %s:  p+lend > s+lens)\n", __func__);
			return NULL;
		}
		if(!memcmp(p,d,lend))
		{
//			printf("********leave %s:  %c\n", __func__, *p);
			return p;
		}
		p++;
	}
}

int get_res_len(char *response_header)
{
printf("********enter get_res_len \n");
	char *reg = "Content-Length: ";
	char *tempstr = (char *)malloc(1024*sizeof(char));
	strncpy(tempstr, response_header, 1024);
//	tempstr[1024]='\0';	
//	printf("%s \n", tempstr);
	char *p1 = sub_str_find(tempstr, reg);
	if(p1 == NULL)
		return -1;
	printf("p1: %c, strlen(reg): %d \n", *p1, strlen(reg));	
	p1 += strlen(reg);
	char *pstart = p1;
	int charlen = 0;
	while(*p1>='0' && *p1<='9' )
	{
		charlen++;
		p1++;
	}
	char *clen = (char *)malloc(charlen*sizeof(char));
	strncpy(clen, pstart, charlen);
	int res_len = atoi(clen);
	printf("res_len is %d\n", res_len);
	free(tempstr);
	free(clen);
printf("********leave get_res_len \n");
	return res_len;
}

void print_hex(char * buff, int len)
{
        int i;
        for (i=0;i<len;i++)
		 printf("%02x",(unsigned char)buff[i]);

        printf("\n");
}

int rsa_generate(RSA *rsa)
{
	ERR_load_crypto_strings(); //If you do not load , the following ERR_error_string() function report null.
	rsa=RSA_generate_key(1024,RSA_3,NULL,NULL);

	return 0;
}

//send http request to remoteserver
int http_request(char *request_buf, char *response_buf, SOCKET sockfd_request)
{
	char *request_buf_encry;
	request_buf_encry = (char *)malloc(128*sizeof(char));

	SOCKET httpsockfd;
	if((httpsockfd=socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
	{
		printf("***http_request(): socket create error!\n");
		return -1;
	}

	sockaddr_in httpsock;
	httpsock.sin_family = AF_INET;
	httpsock.sin_port = htons(6002);
	httpsock.sin_addr.S_un.S_addr = inet_addr(REMOTESERVER); //202.112.50.94
	
	if(connect(httpsockfd, (struct sockaddr*)&httpsock, sizeof(httpsock)) == -1)
	{
		int err =0;
		err = WSAGetLastError();
		if(err != 0)
			printf("err is %d", err);

		printf("***http_request(): socket connect error!\n");
		closesocket(httpsockfd);
		return -1;
	}

	//first, we have to negotiate TODO
	printf("***http_request(): establish!\n");
	int hello_len = 260;
	RSA *rsa;
	ERR_load_crypto_strings(); //If you do not load , the following ERR_error_string() function report null.
	rsa=RSA_generate_key(1024,RSA_3,NULL,NULL);
	printf("N(%d bytes, %d):%s\n",BN_num_bytes(rsa->n), strlen(BN_bn2hex(rsa->n)), BN_bn2hex(rsa->n));
	printf("p(%d bytes):%s\n",BN_num_bytes(rsa->p), BN_bn2hex(rsa->p));
	printf("q(%d bytes):%s\n",BN_num_bytes(rsa->q), BN_bn2hex(rsa->q));
	printf("d(%d bytes):%s\n",BN_num_bytes(rsa->d), BN_bn2hex(rsa->d));
	printf("e(%d bytes):%s\n",BN_num_bytes(rsa->e), BN_bn2hex(rsa->e));
	printf("***http_request(): establish2!\n");
	
	
#ifdef MD5
	//construct client_hello
	char *client_hello = (char *)malloc(hello_len*sizeof(char));
	//sprintf(client_hello, "%d%d%s%s", TYPE_NORMAL, AUTHEN_RSA, BN_bn2hex(rsa->n), BN_bn2hex(rsa->e));
	sprintf(client_hello, "%d%d", TYPE_NORMAL, AUTHEN_MD5);
	strcat(client_hello, BN_bn2hex(rsa->n));
	strcat(client_hello, BN_bn2hex(rsa->e));
	printf("***http_request(): client_hello is: \n");
	//print_hex(client_hello, hello_len);
	printf("%s", client_hello);

	EVP_MD_CTX mdctx;
	const EVP_MD *md;
	unsigned char signature[EVP_MAX_MD_SIZE];
	int md_len, i;

	md = EVP_get_digestbyname("MD5");

	EVP_MD_CTX_init(&mdctx);
	EVP_DigestInit_ex(&mdctx, md, NULL);
	EVP_DigestUpdate(&mdctx, client_hello, strlen(client_hello));
	EVP_DigestFinal_ex(&mdctx, signature, &md_len);
	EVP_MD_CTX_cleanup(&mdctx);

	char *client_header = (char *)malloc((hello_len+md_len)*sizeof(char));
	memcpy(client_header, client_hello, hello_len);
	memcpy(&client_header[260], signature, md_len);
	send(httpsockfd, client_header, hello_len+md_len, 0);

#else
	//construct client_hello
	char *client_hello = (char *)malloc(hello_len*sizeof(char));
	//sprintf(client_hello, "%d%d%s%s", TYPE_NORMAL, AUTHEN_RSA, BN_bn2hex(rsa->n), BN_bn2hex(rsa->e));
	sprintf(client_hello, "%d%d", TYPE_NORMAL, AUTHEN_RSA);
	strcat(client_hello, BN_bn2hex(rsa->n));
	strcat(client_hello, BN_bn2hex(rsa->e));
	printf("***http_request(): client_hello is: \n");
	//print_hex(client_hello, hello_len);
	printf("%s", client_hello);

	//sign
	unsigned int len2=RSA_size(rsa);
	char *signature=(char *)malloc(len2*sizeof(char));
retry:
	char *tmpstr = (char *)malloc(sizeof(client_hello)+1);
	memcpy(tmpstr, client_hello, sizeof(client_hello));
	tmpstr[sizeof(client_hello)] = '\0';
	if(RSA_sign(NID_md5,(unsigned char *)tmpstr,sizeof(client_hello),(unsigned char *)signature,&len2,rsa) == 0)
	{
		unsigned long  code;
		char buff[1024];
		code=ERR_get_error();
		ERR_error_string(code, buff);
		printf("Error:%s\n",buff);
	}
	printf("***http_request(): signature is: \n");
	print_hex(signature, len2);
	//printf("%s", signature);
	//send client_hello
	char *client_header = (char *)malloc((hello_len+len2)*sizeof(char));
	//sprintf(client_header, "%s%s", client_hello, signature);
	memcpy(client_header, client_hello, hello_len);
	memcpy(&client_header[260], signature, len2);
	//strcat(client_header, signature);
	send(httpsockfd, client_header, hello_len+len2, 0);
	//printf("***http_request(): client_header client_hello is: \n");
	//print_hex(&client_header[0], hello_len);
	//printf("%s", client_header);
	printf("***http_request(): client_header signature is: \n");
	print_hex(&client_header[260], len2);
	//printf("%s", &client_header[260]);
//	free(rsa);
	//free(client_hello);
	//free(signature);
	free(client_header);
	printf("***http_request(): establish6!\n");
#endif

	//recieve server_hello
	char *server_header = (char *)malloc((hello_len+len2)*sizeof(char));
	int len_header=recv(httpsockfd, server_header, hello_len+len2, 0);
	printf("***http_request(): establish7: \n");
	print_hex(&server_header[260], len2);
	//pasre server_hello
	RSA *rsa_server = RSA_new();
	int type = atoi(&server_header[0])/10;
	if(type == TYPE_WRONG)
		goto retry;
	int server_auth = atoi(&server_header[1]);
	char *str_n = (char *)malloc(256*sizeof(char));
	strncpy(str_n, &server_header[2], 256);
	BIGNUM *tmp_n = BN_new();
	BN_hex2bn(&tmp_n, str_n);
	rsa_server->n = tmp_n;
	char *str_e = (char *)malloc(2*sizeof(char));
	strncpy(str_e, &server_header[258], 2);
	BIGNUM *tmp_e = BN_new();
	BN_hex2bn(&tmp_e, str_e);
	rsa_server->e = tmp_e;
	printf("type = %d, server_auth = %d \n", type, server_auth);
	printf("N(%d bytes, %d):%s\n",BN_num_bytes(rsa->n), strlen(BN_bn2hex(rsa->n)), BN_bn2hex(rsa->n));
	printf("e(%d bytes):%s\n",BN_num_bytes(rsa->e), BN_bn2hex(rsa->e));
	if(server_auth == AUTHEN_RSA)
	{
		//verify
		char *server_hello = (char *)malloc(hello_len*sizeof(char));
		memcpy(server_hello, &server_header[0], 260);
		//char *signature=(char *)malloc(len2);
		memcpy(signature, &server_header[260], len2);
		printf("***http_request(): signature is: \n");
		print_hex(signature, len2);
		tmpstr = (char *)malloc(sizeof(server_hello)+1);
		memcpy(tmpstr, server_hello, sizeof(server_hello));
		tmpstr[sizeof(server_hello)] = '\0';
		int tmp_i = sizeof(server_hello);
		if(RSA_verify(NID_md5,(unsigned char *)tmpstr, tmp_i,(unsigned char *)signature,len2,rsa_server))//hello_len sizeof(server_hello)
		{
			type = TYPE_NORMAL;
			printf("Signature verified ok\n");
		}
		else
		{
			unsigned long  code;
			char buff[1024];
			code=ERR_get_error();
			ERR_error_string(code, buff);
			printf("Error:%s\n",buff);
			ERR_clear_error();
			type = TYPE_WRONG;
			printf("Signature verified failed\n");
		}
		free(server_header);
		free(str_n);
		free(str_e);
	//	free(rsa_server);
		if(type == TYPE_WRONG)
		{
			//for later provement
			printf("Server cannot be trusted!");
	//		return -1;
		}
	}
	else
	{
#ifdef MD5
		//verify
		char *server_hello = (char *)malloc(hello_len*sizeof(char));
		memcpy(server_hello, &server_header[0], 260);
		memcpy(signature, &server_header[260], md_len);
		printf("***http_request(): signature is: \n");
		print_hex(signature, md_len);

		char *signature2 = (char *)malloc(md_len*sizeof(char));
		EVP_MD_CTX_init(&mdctx);
		EVP_DigestInit_ex(&mdctx, md, NULL);
		EVP_DigestUpdate(&mdctx, server_hello, strlen(server_hello));
		EVP_DigestFinal_ex(&mdctx, signature2, &md_len2);
		EVP_MD_CTX_cleanup(&mdctx);

		if(strcmp(signature, signature2) == 0)
			printf("verification ok! \n");
#endif
	}


	//next, send the request
#ifdef SECURE
	
	if(request_buf_encry == NULL)
		printf("malloc error! \n");
	int total_len = strlen(request_buf);
	int total_iter = (total_len+115)/116;
	int i;
	char *p = request_buf;
	for(i=0; i<total_iter; i++)
	{
		RSA_public_encrypt(116,(unsigned char *)p,(unsigned char *)request_buf_encry,rsa_server,RSA_PKCS1_PADDING);//RSA_PKCS1_PADDING
		{
			unsigned long  code;
			char buff[1024];
			code=ERR_get_error();
			ERR_error_string(code, buff);
			printf("Error:%s\n",buff);
			ERR_clear_error();
		}
		print_hex(request_buf_encry, sizeof(request_buf));
		send(httpsockfd, request_buf_encry, 128, 0);
		recv(httpsockfd, request_buf_encry, 128, 0);///for sync, not real data

		p += 116;
	}
	send(httpsockfd, "end", 4, 0);//for end, not real data
	free(request_buf_encry);
#else
	send(httpsockfd, request_buf, strlen(request_buf), 0);
#endif

#ifdef SECURE
	printf("***http_request(): start to recv \n");
	int nRevd = 0;
	i = 0;
	int recv_len = 0;
	//get header
	response_buf = (char *)malloc(1024*sizeof(char));
	char *buf_decry = (char *)malloc(128*sizeof(char));
	char *tmp_buf = (char *)malloc(128*sizeof(char));
	for(i=0; i<4&&nRevd>=0; i++)
	{
	           nRevd = recv(httpsockfd, tmp_buf, 128, 0);
			   //decrypt
			   RSA_private_decrypt(nRevd, (unsigned char *)tmp_buf, (unsigned char *)buf_decry, rsa, RSA_PKCS1_PADDING);
			   //send back to browser
			   buf_decry[117] = '\0';
			   printf("%s \n", buf_decry);
               send(sockfd_request, buf_decry, 116, 0);
			   recv_len += 116;
               strncpy(&response_buf[i*116], buf_decry, 116);
	}
	i = 0;

	//get length
	int res_len = get_res_len(response_buf);

cont:
	while(nRevd == 128)
	{
		i++;
		nRevd=recv(httpsockfd, tmp_buf, 128, 0);
        if(nRevd < 0)
              goto end;
        
		if(nRevd<128)
		{//last is plaintext
		send(sockfd_request, tmp_buf, nRevd, 0);
		recv_len += nRevd;
//		printf("2***:");
//		print_hex(tmp_buf, nRevd);
		}
		else
		{
		//decrypt
		RSA_private_decrypt(nRevd, (unsigned char *)tmp_buf, (unsigned char *)buf_decry, rsa, RSA_PKCS1_PADDING);
//		printf("2***:");
//		print_hex(buf_decry, strlen(buf_decry));
		//send back to browser
		send(sockfd_request, buf_decry, 116, 0);
		recv_len += 116;
		}
	}

	if(res_len > recv_len)
	{
		nRevd=recv(httpsockfd, tmp_buf, 128, 0);
        if(nRevd < 0)
             goto end;

		if(nRevd < 128)
		{
		send(sockfd_request, tmp_buf, nRevd, 0);
		recv_len += nRevd;
//		printf("3***:");
//		print_hex(tmp_buf, nRevd);
		}
		else
		{
		//decrypt
		RSA_private_decrypt(nRevd, (unsigned char *)tmp_buf, (unsigned char *)buf_decry, rsa, RSA_PKCS1_PADDING);
//		printf("3***:");
//		print_hex(buf_decry, strlen(buf_decry));
		//send back to browser
		send(sockfd_request, buf_decry, 116, 0);
		recv_len += 116;
		}

		goto cont;
	}

end:
	printf("***http_request(): i = %d, nRevd = %d \n", i, nRevd);
#else
	printf("***http_request(): start to recv \n");
	int nRevd;
	int i = 0;
	int recv_len = 0;
	//get header
	response_buf = (char *)malloc(1024*sizeof(char));
	nRevd=recv(httpsockfd, response_buf, 1024, 0);
	send(sockfd_request, response_buf, nRevd, 0);
	printf("***http_request(): header nRevd = %d \n", nRevd);
    recv_len += nRevd;

	//get length
	int res_len = get_res_len(response_buf);

	//get data
/*	while((nRevd=recv(httpsockfd, response_buf, 1024, 0)) == 1024)
	{
		i++;
		//response_buf += nRevd;

		send(sockfd_request, response_buf, nRevd, 0);
		//printf("nRevd = %d \n", nRevd);
		//printf("***http_request(): revd: %s", response_buf);
	}
*/
cont:
		while(nRevd == 1024)
		{
		i++;
		nRevd=recv(httpsockfd, response_buf, 1024, 0);
        if(nRevd < 0)
              goto end;
        recv_len += nRevd;
	
		//send back to localserver
		send(sockfd_request, response_buf, nRevd, 0);

		}
	
	if(res_len > recv_len)
	{
		nRevd=recv(httpsockfd, response_buf, 1024, 0);
        if(nRevd < 0)
             goto end;
		recv_len += nRevd;
		send(sockfd_request, response_buf, nRevd, 0);
		goto cont;
	}

end:
	printf("***http_request(): i = %d, nRevd = %d \n", i, nRevd);
#endif
	free(response_buf);
	closesocket(httpsockfd);
	closesocket(sockfd_request);
	return 0;
}

int _tmain(int argc, _TCHAR* argv[])
{
	init_socket();
	SOCKET sockfd = create_listen_socket();

	SOCKET sockfd_request;
	struct sockaddr_in sockaddr_request;
	int addrlen;
	if((sockfd_request=accept(sockfd, (struct sockaddr*)&sockaddr_request, &addrlen)) == NULL)
	{
		printf("TODO: accept error!\n");
	}
	printf("ip = %ld \n", sockaddr_request.sin_addr.S_un.S_addr);

	//wait for request
	printf("***from browser: start to recv \n");
	int nRevd;
	char buf[1024];
	while((nRevd=recv(sockfd_request, buf, 1024, 0)) == 1024)
	{
		//printf("nRevd = %d \n", nRevd);
		//printf("revd: %s", buf);
	}

	//buf[nRevd] = '\0';
	//printf("revd: %s \n", buf);
	printf("***from browser: nRevd = %d \n", nRevd);



	//http request
	char *response_buf;
	http_request(buf, response_buf, sockfd_request);

//	printf("***send back to browser: %s \n", response_buf);
	//send back to requester
//	send(sockfd_request, response_buf, strlen(response_buf), 0);


	closesocket(sockfd_request);
	::WSACleanup();


	//wait for exit
	int a;
	scanf("%c", &a);

	
	
	return 0;
}

