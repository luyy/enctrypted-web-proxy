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
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/objects.h>

#define SECURE

#define TYPE_NORMAL 1
#define TYPE_WRONG 2

#define AUTHEN_RSA 1
#define AUTHEN_MD5 2

#define DEBUG_P

#ifdef DEBUG_P
#define DEBUG(s) printf("%s \n", s)
#else
#define DEBUG(s) {}
#endif

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

void print_hex(char * buff, int len)
{
        int i;
        for (i=0;i<len;i++)
		 printf("%02x",(unsigned char)buff[i]);

        printf("\n");
}

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
	
	//establish stage
	DEBUG("***enter establish");
	int hello_len = 260;
	RSA *rsa;
	ERR_load_crypto_strings(); //If you do not load , the following ERR_error_string() function report null.
	rsa=RSA_generate_key(1024,RSA_3,NULL,NULL);
	printf("N(%d bytes, %d):%s\n",BN_num_bytes(rsa->n), strlen(BN_bn2hex(rsa->n)), BN_bn2hex(rsa->n));
	printf("p(%d bytes):%s\n",BN_num_bytes(rsa->p), BN_bn2hex(rsa->p));
	printf("q(%d bytes):%s\n",BN_num_bytes(rsa->q), BN_bn2hex(rsa->q));
	printf("d(%d bytes):%s\n",BN_num_bytes(rsa->d), BN_bn2hex(rsa->d));
	printf("e(%d bytes):%s\n",BN_num_bytes(rsa->e), BN_bn2hex(rsa->e));
	DEBUG("***enter establish2");
	//recieve client_hello
	unsigned int len2 = RSA_size(rsa);
	char *client_header = (char *)malloc((hello_len+len2)*sizeof(char));
	int len_header=recv(sock_localserver, client_header, hello_len+len2, 0);
	DEBUG("***enter establish3");
	//pasre client_hello
	//RSA *rsa_client = (RSA *)malloc(sizeof(*rsa_client));
	RSA *rsa_client = RSA_new();
	int type = atoi(&client_header[0])/10; //first two bytes are numbers, the first number is type, second authentication algorithm
	int client_auth = atoi(&client_header[1]);
	char *str_n = (char *)malloc(256*sizeof(char));
	memcpy(str_n, &client_header[2], 256);
//	str_n[257] = '\0';
//	printf("str_n is: %s", str_n);
	DEBUG("***enter establish4: ");
	BIGNUM *tmp_n;
	tmp_n = BN_new();
	BN_hex2bn(&tmp_n, str_n);
	DEBUG("***enter establish51");
	rsa_client->n = tmp_n;
	DEBUG("***enter establish5");
	char *str_e = (char *)malloc(2*sizeof(char));
	memcpy(str_e, &client_header[258], 2);
	BIGNUM *tmp_e;
	tmp_e = BN_new();
	BN_hex2bn(&tmp_e, str_e);
	rsa_client->e = tmp_e;
	printf("type = %d, server_auth = %d\n", type, client_auth);
	printf("N(%d bytes, %d):%s\n",BN_num_bytes(rsa_client->n), strlen(BN_bn2hex(rsa_client->n)), BN_bn2hex(rsa_client->n));
	printf("e(%d bytes):%s\n",BN_num_bytes(rsa_client->e), BN_bn2hex(rsa_client->e));
	//verify
	printf("%d = 260 + %d \n", len_header, len2);
	char *client_hello = (char *)malloc(hello_len*sizeof(char));
	memcpy(client_hello, &client_header[0], 260);
	DEBUG("***enter establish6");
	char *signature=(char *)malloc(len2*sizeof(char));
	memcpy(signature, &client_header[260], len2);
	DEBUG("***enter establish7");
printf("****signature : \n");
        print_hex(signature, len2);
        printf("****client_header is : \n");
        print_hex(&client_header[260], len2);
	if(RSA_verify(NID_md5, (unsigned char *)client_hello, hello_len, (unsigned char *)signature, len2, rsa_client))
	{
		type = TYPE_NORMAL;
		printf("Signature verified ok\n");
	}
	else
	{
		unsigned long code;
		char buf[1024];
		code=ERR_get_error();		
		ERR_error_string(code, buf);
		printf("Verify Error: %s\n", buf);
		type = TYPE_WRONG;
		printf("Signature verified failed\n");
	}
	free(client_hello);
	free(client_header);
	free(str_n);
	free(str_e);
	free(rsa_client);
	DEBUG("***enter establish8");
	//construct server_hello
	char *server_hello = (char *)malloc(hello_len*sizeof(char));
	//sprintf(server_hello, "%d%d%s%s", type, AUTHEN_RSA, BN_bn2hex(rsa->n), BN_bn2hex(rsa->e));
	sprintf(server_hello, "%d%d", TYPE_NORMAL, AUTHEN_RSA);
	strcat(server_hello, BN_bn2hex(rsa->n));
	strcat(server_hello, BN_bn2hex(rsa->e));
	//sign
	printf("***len2 = %d, sizeof(server_hello) = %d \n", len2, sizeof(server_hello));
	//if(signature != NULL)
	//	free(signature);
	//signature = (char *)malloc(128*sizeof(char));
	if(RSA_sign(NID_md5, (unsigned char *)server_hello, hello_len, (unsigned char *)signature, &len2, rsa) == 0)
	{
		unsigned long code;
		char buf[1024];
		code=ERR_get_error();		
		ERR_error_string(code, buf);
		printf("Sign Error: %s\n", buf);
	}
	//send client_hello
	char *server_header = (char *)malloc((hello_len+len2)*sizeof(char));
	//sprintf(server_header, "%s%s", server_hello, signature);
	memcpy(server_header, server_hello, hello_len);
	memcpy(&server_header[hello_len], signature, len2);
	send(sock_localserver, server_header, hello_len+len2, 0);
	printf("****signature : \n");
	print_hex(signature, len2);
	printf("****server_header is : \n");
	print_hex(&server_header[260], len2);
	free(rsa);
	//free(server_hello);
	//free(signature);
	//free(server_header);
	DEBUG("***enter establish9");
	if(type == TYPE_WRONG)
	{
		printf("client not trusted! \n");
//		return (void *)0;
	}


		printf("request: \n");
		int i = 0;
		char buf[1024];
		while((nRevd=recv(sock_localserver, buf, 1024, 0)) == 1024)
		{
			i++;
	//		printf("%s", buf);
		}
	//	buf[nRevd] = '\0';
#ifdef SECURE
		char buf_decry[1024];
		RSA_private_decrypt(nRevd,(unsigned char *)buf,(unsigned char *)buf_decry,rsa,RSA_PKCS1_PADDING);
		printf("%s \n", buf_decry);
		printf("request buf end: i=%d, nRevd = %d \n", i, nRevd);

		//http request
		//char *response_buf = (char *)malloc(4096*sizeof(char));
		//char *response_header = NULL;
		//char *response_buf = NULL;
		//int response_len;
		//http_request(buf, response_header, response_buf, &response_len);
		http_request(buf_decry, sock_localserver);
#else
		printf("request buf end: i=%d, nRevd = %d \n", i, nRevd);
		http_request(buf, sock_localserver);
#endif
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
    struct addrinfo *result;//(struct addrinfo *)malloc(sizeof(*result));
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
