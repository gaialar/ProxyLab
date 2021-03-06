/*
 * proxy.c - CS:APP Web proxy
 *
 * TEAM MEMBERS:
 *     Steinar Eyþór Valsson, steinarv12@ru.is
 *     Ólafur Konráðsson, olafurk12@ru.is 
 *     Hulda Lárusdóttir, huldal12@ru.is
 * 
 * IMPORTANT: Give a high level description of your code here. You
 * must also provide a header comment at the beginning of each
 * function that describes what that function does.
 */ 

#include "csapp.h"
#include <arpa/inet.h>

#define RESET   "\033[0m"       /* Rest */
#define RED     "\033[31m"      /* Red */
#define GREEN   "\033[32m"      /* Green */
#define YELLOW  "\033[33m"      /* Yellow */

/*
 * Function prototypes
 */
int parse_uri(char *uri, char *target_addr, char *path);
void format_log_entry(char *logstring, struct sockaddr_in *sockaddr, char *uri, int size);

/* Our Functions */

void processReq(int fd, int port);
char* toIp(int ip, char* buf);
void handleGET(int fd, int port, char* url, char* buf);
void createGET(int client, char* url, char* buf);
int open_clientfd_ts(int port, char* host);
ssize_t Rio_readn_w(int fd, void *ptr, size_t nbytes);
void Rio_writen_w(int fd, void *usrbuf, size_t n);
ssize_t Rio_readlineb_w(rio_t *rp, void *usrbuf, size_t maxlen);

/* Help functions */
void warn(char* code, char* warn);
void error(char* code, char* error);

/* Functions from tiny.c */

void serve_static(int fd, char *filename, int filesize);
void get_filetype(char *filename, char *filetype);
/* 
 * main - Main routine for the proxy program 
 */
int main(int argc, char **argv)
{
    int port, listenfd, connfd;
    socklen_t clientlen = sizeof(struct sockaddr_in);
    struct sockaddr_in clientaddr;
	char ipBuf[4];

    /* Check arguments */
    if (argc != 2) {
		fprintf(stderr, "Usage: %s <port number>\n", argv[0]);
		exit(0);
    }

    port = atoi(argv[1]);
    listenfd = open_listenfd(port);
    printf("Listening on port: %d\n",port);

    while(1){
        connfd = Accept(listenfd, (SA *)&clientaddr, &clientlen);
    

        if(connfd > 0){
            printf("Accepting connection from: %s \n", toIp(clientaddr.sin_addr.s_addr, ipBuf));
			processReq(connfd, port);
        } else {
			printf("Error on connection: %s \n", strerror(errno));
		}
    }

    printf("Good Bye!\n");
    exit(0);
}

/*
 * processReq - 
 *
 *
 */
void processReq(int fd, int port) 
{
    int is_static;
    struct stat sbuf;
    char buf[MAXLINE], method[MAXLINE], uri[MAXLINE], version[MAXLINE];
    char filename[MAXLINE], cgiargs[MAXLINE];
    rio_t client;	

	/* Read request line and headers */
    Rio_readinitb(&client, fd);
    Rio_readlineb_w(&client, buf, MAXLINE);
    sscanf(buf, "%s %s %s", method, uri, version);
    is_static = parse_uri(uri, filename, cgiargs);
    printf("uri: %s\nhostname: %s\npathname: %s\n", uri, filename, cgiargs);

    printf("Type: %s\nMethod: %s\n\n", is_static ? "Static" : "Dynamic", method);

    if (strcmp(method, "GET") == 0) {
        printf("Get method called \n");                         
        handleGET(fd, port, uri, buf);
        
        return;
    } 
                                                       
    /* Parse URI from GET request */
    if (stat(filename, &sbuf) < 0) {                     
        printf("404, File not found \n");
        return;
    }

    if (is_static) { /* Serve static content */
        if (!(S_ISREG(sbuf.st_mode)) || !(S_IRUSR & sbuf.st_mode)) { //line:netp:doit:readable
            //return;
        }
        serve_static(fd, filename, sbuf.st_size);
    }
    else { /* Serve dynamic content */
        if (!(S_ISREG(sbuf.st_mode)) || !(S_IXUSR & sbuf.st_mode)) { //line:netp:doit:executable
            return;
        }
    }
}

void handleGET(int fd, int port, char* url, char* buf)
{
    int clientfd;

    if((clientfd = open_clientfd_ts(port, url)) < 0) {
        error("Clinet: ", "Unable to connect to client");
    }

    Rio_readinitb(&fd, clientfd);
    createGET(clientfd, url, buf);
}

void createGET(int client, char* url, char* buf)
{
    Rio_writen_w(client, "GET ", strlen("GET "));
    Rio_writen_w(client, url, strlen(url));
    Rio_writen_w(client, " ", strlen(" "));
    Rio_writen_w(client, "HTTP/1.0", strlen("HTTP/1.0"));
    Rio_writen_w(client, "\r\n", strlen("\r\n"));

    Rio_writen_w(client, buf, strlen(buf));
    Rio_writen_w(client, "\r\n", 2);
}

int open_clientfd_ts(int port, char* hostname) {
    int clientfd;
    struct sockaddr_in serveraddr;
    struct hostent *ch;

    if ((clientfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        return -1;

    
    if ((ch = gethostbyname(hostname)) == 0) {
        puts(hostname);
    } else
        warn("Host: ", "Unable to get name");
           
    /* Connet to server */
    if (connect(clientfd, (SA *) &serveraddr, sizeof(serveraddr)) < 0)
        return -1;
    
    return clientfd;
}

void serve_static(int fd, char *filename, int filesize)
{
    int srcfd;
    char *srcp, filetype[MAXLINE], buf[MAXBUF];
    
    /* Send response headers to client */
    get_filetype(filename, filetype);       //line:netp:servestatic:getfiletype
    sprintf(buf, "HTTP/1.0 200 OK\r\n");    //line:netp:servestatic:beginserve
    sprintf(buf, "%sServer: Tiny Web Server\r\n", buf);
    sprintf(buf, "%sContent-length: %d\r\n", buf, filesize);
    sprintf(buf, "%sContent-type: %s\r\n\r\n", buf, filetype);
    Rio_writen(fd, buf, strlen(buf));       //line:netp:servestatic:endserve
   
    /* Send response body to client */
    srcfd = Open(filename, O_RDONLY, 0);    //line:netp:servestatic:open
    srcp = Mmap(0, filesize, PROT_READ, MAP_PRIVATE, srcfd, 0);//line:netp:servestatic:mmap
    Close(srcfd);                           //line:netp:servestatic:close
    Rio_writen_w(fd, srcp, filesize);         //line:netp:servestatic:write
    Munmap(srcp, filesize);                 //line:netp:servestatic:munmap
}

void get_filetype(char *filename, char *filetype)
{
    if (strstr(filename, ".html"))
        strcpy(filetype, "text/html");
    else if (strstr(filename, ".gif"))
        strcpy(filetype, "image/gif");
    else if (strstr(filename, ".jpg"))
        strcpy(filetype, "image/jpeg");
    else
        strcpy(filetype, "text/plain");
}

/*
 * parse_uri - URI parser
 * 
 * Given a URI from an HTTP proxy GET request (i.e., a URL), extract
 * the host name, path name, and port.  The memory for hostname and
 * pathname must already be allocated and should be at least MAXLINE
 * bytes. Return -1 if there are any problems.
 */
int parse_uri(char *uri, char *hostname, char *pathname)
{
    char *hostbegin;
    char *hostend;
    char *pathbegin;
    int len;

    if (strncasecmp(uri, "http://", 7) != 0) {
	    hostname[0] = '\0';
	    return -1;
    }
       
    /* Extract the host name */
    hostbegin = uri + 7;
    hostend = strpbrk(hostbegin, " :/\r\n\0");
    len = hostend - hostbegin;
    strncpy(hostname, hostbegin, len);
    hostname[len] = '\0';
    
    /* Extract the port number */
    int port = 80; /* default */
    
    if (*hostend == ':')   
	    port = atoi(hostend + 1);

    /* Extract the path */
    pathbegin = strchr(hostbegin, '/');
    
    if (pathbegin == NULL) {
	    pathname[0] = '\0';
    }
    else {
	    pathbegin++;	
	    strcpy(pathname, pathbegin);
    }

    return 0;
}

/*
 * format_log_entry - Create a formatted log entry in logstring. 
 * 
 * The inputs are the socket address of the requesting client
 * (sockaddr), the URI from the request (uri), and the size in bytes
 * of the response from the server (size).
 */
void format_log_entry(char *logstring, struct sockaddr_in *sockaddr, char *uri, int size)
{
    time_t now;
    char time_str[MAXLINE];
    unsigned long host;
    unsigned char a, b, c, d;

    /* Get a formatted time string */
    now = time(NULL);
    strftime(time_str, MAXLINE, "%a %d %b %Y %H:%M:%S %Z", localtime(&now));

    /* 
     * Convert the IP address in network byte order to dotted decimal
     * form. Note that we could have used inet_ntoa, but chose not to
     * because inet_ntoa is a Class 3 thread unsafe function that
     * returns a pointer to a static variable (Ch 13, CS:APP).
     */
    host = ntohl(sockaddr->sin_addr.s_addr);
    a = host >> 24;
    b = (host >> 16) & 0xff;
    c = (host >> 8) & 0xff;
    d = host & 0xff;


    /* Return the formatted log entry string */
    sprintf(logstring, "%s: %d.%d.%d.%d %s %d", time_str, a, b, c, d, uri, size);
}

char* toIp(int ip, char* buf)
{
	unsigned char bytes[4];

    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;
	sprintf(buf, "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);
	
	return buf;
}

/*Threadsafe wrapper for Rio_readn*/
ssize_t Rio_readn_w(int fd, void *ptr, size_t nbytes)
{
    ssize_t n;
    
    if((n = rio_readn(fd, ptr, nbytes)) < 0)
    {
        error("read error", "rio_readn_w failed to read.");
        return 0;
    }

    return n;
}

/*Threadsafe wrapper for Rio_writen*/
void Rio_writen_w(int fd, void *usrbuf, size_t n)
{    
    if(rio_writen(fd, usrbuf, n) != n)
    {
        error("write error", "rio_writen_w failed to write.");
        //return;
    }
}

/*Treadsafe wrapper for Rio_readlineb*/
ssize_t Rio_readlineb_w(rio_t *rp, void *usrbuf, size_t maxlen)
{
    ssize_t rc;
    
    if((rc = rio_readlineb(rp, usrbuf, maxlen)) < 0)
    {
        error("readline error", "rio_readlineb_w failed to read.");
        return 0;
    }

    return rc;
}

/*printer function for warnings, warnings are printed in yellow*/
void warn(char* code, char* warn) 
{
    printf(YELLOW);
    printf("%s: %s", code, warn);
    printf(RESET "\n"); 
}

/*printer function for errors, errors are printed in red*/
void error(char* code, char* error) 
{
    printf(RED);
    printf("%s: %s", code, error);
    printf(RESET "\n");
}
