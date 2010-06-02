// encrypted-web-proxy-localserver.cpp : 定义控制台应用程序的入口点。
//

/*
* encrypted-web-server-localserver.cpp
*		This file listens to the requests at some port, encrypts the requests with ssl algorithms and forwards them to remote server.
*		Local server implemented on Windows, while remote on Linux.
*
*	Youyou Lu (luyouyou87@gmail.com)
*	2010/06/01
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
		printf("socket create error!\n");
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
		printf("socket bind error!\n");
		closesocket(sockfd);
		exit(1);
	}

	//listen
	if(listen(sockfd, 1) == SOCKET_ERROR)
	{
		printf("socket listen error!\n");
		closesocket(sockfd);
		exit(1);
	}

	return sockfd;
}

//send http request to
int http_request(char *request_buf, char *response_buf)
{
	SOCKET httpsockfd;
	if((httpsockfd=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET)
	{
		printf("http_request(): socket create error!\n");
		return -1;
	}

	sockaddr_in httpsock;
	httpsock.sin_family = AF_INET;
	httpsock.sin_port = htons(6002);
	httpsock.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
	
	if(connect(httpsockfd, (struct sockaddr*)&httpsock, sizeof(httpsock)) == -1)
	{
		printf("http_request(): socket connect error!\n");
		closesocket(httpsockfd);
		return -1;
	}

	send(httpsockfd, request_buf, strlen(request_buf), 0);

	printf("http_request(): start to recv \n");
	int nRevd;
	//char buf[1024];
	int i = 0;
	while((nRevd=recv(httpsockfd, response_buf, 1024, 0)) == 1024)
	{
		i++;
		response_buf += nRevd;
		//printf("nRevd = %d \n", nRevd);
		printf("http_request(): revd: %s", response_buf);
	}

	response_buf[nRevd] = '\0';
	printf("http_request(): revd: %s \n", response_buf);
	printf("http_request(): i = %d, nRevd = %d \n", i, nRevd);

	closesocket(httpsockfd);
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
	printf("start to recv \n");
	int nRevd;
	char buf[1024];
	while((nRevd=recv(sockfd_request, buf, 1024, 0)) == 1024)
	{
		//printf("nRevd = %d \n", nRevd);
		printf("revd: %s", buf);
	}

	buf[nRevd] = '\0';
	printf("revd: %s \n", buf);
	printf("nRevd = %d \n", nRevd);

	int err =0;
	err = WSAGetLastError();
	printf("err is %d", err);

	//http request
	char response_buf[1024];
	http_request(buf, response_buf);

	//send back to requester
	send(sockfd_request, response_buf, strlen(response_buf), 0);

	//wait for exit
	int a;
	scanf("%c", &a);

	closesocket(sockfd_request);
	::WSACleanup();
	return 0;
}

