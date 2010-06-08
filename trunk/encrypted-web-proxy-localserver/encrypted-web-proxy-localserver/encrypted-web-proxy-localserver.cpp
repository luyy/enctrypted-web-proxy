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

#define LOCALPORT 6000
//#define REMOTEPORT 6002 //not used now

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

//send http request to
int http_request(char *request_buf, char *response_buf, SOCKET sockfd_request)
{
	SOCKET httpsockfd;
	if((httpsockfd=socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
	{
		printf("***http_request(): socket create error!\n");
		return -1;
	}

	sockaddr_in httpsock;
	httpsock.sin_family = AF_INET;
	httpsock.sin_port = htons(6002);
	httpsock.sin_addr.S_un.S_addr = inet_addr("10.0.1.35"); //202.112.50.94
	
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

	send(httpsockfd, request_buf, strlen(request_buf), 0);

	printf("***http_request(): start to recv \n");
	int nRevd;
	int i = 0;
	int recv_len = 0;
	//get header
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
	//response_buf[nRevd] = '\0';
	//printf("***http_request(): revd: %s \n", response_buf);
	printf("***http_request(): i = %d, nRevd = %d \n", i, nRevd);

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
	char response_buf[1024];
	http_request(buf, response_buf, sockfd_request);

//	printf("***send back to browser: %s \n", response_buf);
	//send back to requester
//	send(sockfd_request, response_buf, strlen(response_buf), 0);

	//wait for exit
	int a;
	scanf("%c", &a);

	closesocket(sockfd_request);
	::WSACleanup();
	return 0;
}

