#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <assert.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <regex.h>
#include <netdb.h>
#include <pthread.h>


pthread_t thid;

struct sock_arg
{
    int sock;
};

struct ip_t
{
	int a;
	int b;
	int c;
	int d;
};

void *handle_localserver_request_thread(void *arg);
//void handle_localserver_request(int sock_localserver);
//int http_request(char *request_buf, char *response_header, char *response_buf, int *response_len);
int http_request(char *request_buf, int localserver_sock);

int listen_localserver_init()
{
	int sockfd;
	struct sockaddr_in sin;
	
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_port = htons(6002);

	if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		printf("init error! \n");
		return errno;
	}

	if(bind(sockfd, (struct sockaddr*)&sin, sizeof(sin)) < 0)
	{
		printf("bind error(%d): %s! \n", errno, strerror(errno));
		return errno;
	}

	if(listen(sockfd, 1) < 0)
	{
		printf("listen error! \n");
		return errno;
	}

        while(1)
        {
	    int sock_localserver;
	    if((sock_localserver=accept(sockfd, NULL, NULL)) < 0)
	    {
		printf("accept error! \n");
		return errno;
	    }

	    //handle_localserver_request(sock_localserver);
            struct sock_arg sa;
            sa.sock = sock_localserver;
            int err = pthread_create(&thid, NULL, handle_localserver_request_thread, (void *)&sa);
            if(err != 0)
            {
                printf("thread create error: %d", sock_localserver);

            }
        }

        printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!1");
	return 0;
}

void * handle_localserver_request_thread(void *arg)
//void handle_localserver_request(int sock_localserver)
{
    struct sock_arg *sa = (struct sock_arg *)arg;
    int sock_localserver = sa->sock;
	int nRevd;

	while(1)
	{
            if(sock_localserver == 0)
                break;

		printf("request: \n");
		int i = 0;
		char buf[4096];
		while((nRevd=recv(sock_localserver, buf, 4096, 0)) == 4096)
		{
			i++;
	//		printf("%s", buf);
		}
	//	buf[nRevd] = '\0';
		printf("%s \n", buf);
		printf("request buf end: i=%d, nRevd = %d \n", i, nRevd);

		//http request
		//char *response_buf = (char *)malloc(4096*sizeof(char));
		//char *response_header = NULL;
		//char *response_buf = NULL;
		//int response_len;
		//http_request(buf, response_header, response_buf, &response_len);
		http_request(buf, sock_localserver);
	//	printf("Response: %s \n", response_header);
	//	printf("Response: %s \n", response_buf);

		//send back to localserver
	/*	printf("______1");
		strcat(response_header, response_buf);
		printf("______2");
		send(sock_localserver, response_header, response_len, 0);
		printf("response is (len-%d) :\n %s", response_len, response_header);
		free(response_header);
		free(response_buf);
	*/
		printf("*************this request end! \n\n");
	}

        printf("**************************thread end! \n");
        return ((void *)0);
}

int dns_query(const char* url, struct ip_t *ip)
{
    struct addrinfo *result = NULL;
    int ret;
    struct addrinfo addr;

    memset(&addr, 0 , sizeof(addr));
    addr.ai_socktype = SOCK_STREAM;

    ret = getaddrinfo(url, NULL, &addr, &result);
    if (!ret)
    {
        struct addrinfo *pCurr = result;
        printf("the \'%s\' ip is:\n", url);
        for (; pCurr; pCurr = pCurr->ai_next)
        {	
		printf("%s\n", inet_ntoa(((struct sockaddr_in*)(pCurr->ai_addr))->sin_addr));
		if(sscanf(inet_ntoa(((struct sockaddr_in*)(pCurr->ai_addr))->sin_addr), "%d.%d.%d.%d", &ip->a, &ip->b, &ip->c, &ip->d) == 4)
			break;
        }
    }

    return 0;
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
printf("********enter %s \n", __func__);
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
printf("********leave %s \n", __func__);
	return res_len;
}

//send http request to
//int http_request(char *request_buf, char *response_header, char *res_buf, int *response_len)
int http_request(char *request_buf, int localserver_sock)
{
	int httpsockfd;
	if((httpsockfd=socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		printf("http_request(): socket create error!\n");
		return -1;
	}

	//get domain name
	char *remote_name = (char *)malloc(64*sizeof(char));
	char *p, *start;
	int len = 0;
	int flag = 0;
	for(p=request_buf;;)
	{
		if(*p == ':')
		{
			p += 3;
			start = p;
			flag = 1;
			continue;
		}
		if(flag==1 && *p=='/')
			break;
		if(flag == 1)
			len++;
		p++;
	}
	strncpy(remote_name, start, len);
	remote_name[len] = '\0';
	printf("remote_name(%d) is %s \n", len, remote_name);

	//get ip from dns
	struct sockaddr_in httpsock;
	httpsock.sin_family = AF_INET;
	httpsock.sin_port = htons(80);
	struct ip_t remote_ip;
	dns_query(remote_name, &remote_ip);
	free(remote_name);
	httpsock.sin_addr.s_addr = htonl(remote_ip.a<<24|remote_ip.b<<16|remote_ip.c<<8|remote_ip.d);
	//httpsock.sin_addr.s_addr = htonl(119<<24|75<<16|213<<8|51);
	
	//connect to website
	if(connect(httpsockfd, (struct sockaddr*)&httpsock, sizeof(httpsock)) < 0)
	{
		printf("http_request(): socket connect error(%d): %s! \n", errno, strerror(errno));
		return -1;
	}

	//send request to website
	send(httpsockfd, request_buf, strlen(request_buf), 0);
	//printf("send: %s \n", request_buf);
	
/*	char *file = "index.html";
	int fd = open(file, O_RDWR|O_CREAT);
	if(fd < 0)
	{
		perror("open error! \n");
	}
*/
	//get response header
	int nRevd = 0;
	int i = 0;
	int recv_len = 0;
	printf("http_request() revd:\n");
	char *response_buf = (char *)malloc(1024*sizeof(char));
	nRevd = recv(httpsockfd, response_buf, 1024, 0);
	if(nRevd < 0)
            goto end;
        recv_len += nRevd;
//	write(fd, response_buf, nRevd);

	//senb back to localserver
	send(localserver_sock, response_buf, nRevd, 0);

	//get res_len
        int res_len = get_res_len(response_buf);
        //int res_len = 1888;

	//recv answer from website
	//res_len = (res_len+1023)/1024*1024;
	printf("YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY %d\n", res_len);
	//char *response_buf = (char *)malloc(res_len*sizeof(char));
	//printf("YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY\n");
/*	if(res_len>0)
	{
		while(res_len > 0)
		{
		i++;
		nRevd=recv(httpsockfd, response_buf, 1024, 0);
		res_len -= nRevd;

		//send back to localserver
		send(localserver_sock, response_buf, nRevd, 0);
	
		}
	
	}
	else
*/	{
cont:
		while(nRevd == 1024)
		{
		i++;
		nRevd=recv(httpsockfd, response_buf, 1024, 0);
                if(nRevd < 0)
                    goto end;
                recv_len += nRevd;
//		write(fd, response_buf, nRevd);
	
		//send back to localserver
		send(localserver_sock, response_buf, nRevd, 0);
	
//		if(nRevd < 1024)
//			break;
//		response_buf += nRevd;
//		printf("%s", response_buf);
		}
	}
	
	if(res_len > recv_len)
	{
		nRevd=recv(httpsockfd, response_buf, 1024, 0);
                if(nRevd < 0)
                    goto end;
		recv_len += nRevd;
//		write(fd, response_buf, nRevd);
		send(localserver_sock, response_buf, nRevd, 0);
		goto cont;
	}
//	if(nRevd == 1024)
//		nRevd = 1023;
//	response_buf[nRevd] = '\0';
//	printf("%s \n", response_buf);
	//*response_len = i*1024+nRevd;

end:
        printf("b9999999999999999999999999999999999\n");
	free(response_buf);
//	close(fd);
	printf("http_request(): i = %d, nRevd = %d \n", i, nRevd);
//	strcat(response_header, res_buf);
printf("h9999999999999999999999999999999999\n");
	return 0;
}

//read file
int read_file(char *file)
{
	int fd = open(file, O_RDWR);
	char buf[1024];
	int ret = 0;
	while((ret=read(fd, buf, 1024)) > 0)
	{
		printf("%s", buf);
	}
	return 0;
}

int main()
{
//test
/*char *s = "helokkd \r\n Content-Length: 666 \r\n";
char *d = "Content-Length";
char *p = sub_str_find(s, d);
printf("%s \n", p);
*/

/*char *a = (char *)malloc(5*sizeof(char));
char *b = (char *)malloc(5*sizeof(char));
strncpy(a, "hel", 3);
strncpy(b, "youy", 4);
strcat(a, b);
printf("%s \n", a);
free(a);
free(b);
*/

	listen_localserver_init();

//	read_file("index.html");
	//test http_request
//	char *reqbuf = "GET http://www.baidu.com/ HTTP/1.1\r\nHost:www.baidu.com\r\n\r\n";
//	char *respose = (char *)malloc(4096*sizeof(char));
//	http_request(reqbuf, respose);

	return 0;
}
