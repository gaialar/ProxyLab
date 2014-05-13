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

/* Macros */
#define NTHREADS 50
#define SBUFSIZE 50
#define RESET   "\033[0m"       /* Rest */
#define RED     "\033[31m"      /* Red */
#define GREEN   "\033[32m"      /* Green */
#define YELLOW  "\033[33m"      /* Yellow */
#define MIN(a,b) (((a)<(b))?(a):(b))

/* struct for trheads, CSAPP 12.5.4*/
typedef struct {
    int *buf;          /* Buffer array */         
    int n;             /* Maximum number of slots */
    int front;         /* buf[(front+1)%n] is first item */
    int rear;          /* buf[rear%n] is last item */
    sem_t mutex;       /* Protects accesses to buf */
    sem_t slots;       /* Counts available slots */
    sem_t items;       /* Counts available items */
} sbuf_t;

/* Global variables */
sbuf_t sbuf;    /* Shared buffer for trheads */
pthread_mutex_t lock;

/* Function prototypes */
int parse_uri(char *uri, char *target_addr, char *path, int *port);
void format_log_entry(char *logstring, struct sockaddr_in *sockaddr, char *uri, int size);

/* Our Functions */
int process_req(int fd);
char* to_ip(int ip, char* buf);
void handle_GET(rio_t fd, int serverfd, char* cgiargs, char* uri, char* filename, char* method, char* version, int port);
void send_GET(rio_t *client, int serverfd, char* url, char* filename, char* method, char* version, int port);
void send_header(rio_t *server, int serverfd, int *status, int *contentlength, char *encoding);
void send_payLoad(rio_t *server, int serverfd, int contentlength, char *encoding);
int open_clientfd_ts(char* host, int port);
void *thread(void *vargp);
void logWrite(char * toLog);
void *thread_init(void *vargp);

/* Help functions */
void warn(char* code, char* warn);
void error(char* code, char* error);
ssize_t Rio_readn_w(int fd, void *ptr, size_t nbytes);
void Rio_writen_w(int fd, void *usrbuf, size_t n);
ssize_t Rio_readlineb_w(rio_t *rp, void *usrbuf, size_t maxlen);

/* Functions from tiny.c */
void serve_static(int fd, char *filename, int filesize);
void get_filetype(char *filename, char *filetype);

/* Threads, sbuf.c CSAPP  12.5.4 */
void sbuf_init(sbuf_t *sp, int n);
void sbuf_deinit(sbuf_t *sp);
void sbuf_insert(sbuf_t *sp, int item);
int sbuf_remove(sbuf_t *sp); 

/* 
 * main - Main routine for the proxy program 
 */
int main(int argc, char **argv) {
    int port, listenfd, *connfd;
    socklen_t clientlen = sizeof(struct sockaddr_in);
    struct sockaddr_in clientaddr;
	char ipBuf[4];
    pthread_t tid;
    int i;

    signal(SIGPIPE, SIG_IGN);

    pthread_mutex_init(&lock, NULL);
    
    /* Check arguments */
    if (argc != 2) {
		fprintf(stderr, "Usage: %s <port number>\n", argv[0]);
		exit(0);
    }

    port = atoi(argv[1]);
    
    sbuf_init(&sbuf, SBUFSIZE);
    for(i = 0; i < NTHREADS; i++) {
        if(pthread_create(&tid, NULL, thread_init, NULL/*(void*)connfd*/) < 0) {
                error("Thread", "Could not creat thread");
            }
    }

    listenfd = open_listenfd(port);
    printf("Listening on port: %d\n",port);

    while(1) {
        connfd = Malloc(sizeof(int));
        *connfd = Accept(listenfd, (SA *)&clientaddr, &clientlen);

        if(connfd > 0) {
            printf("Accepting connection from: %s \n", to_ip(clientaddr.sin_addr.s_addr, ipBuf));
		    sbuf_insert(&sbuf, *connfd);
            /*
            if(pthread_create(&tid, NULL, thread, (void*)connfd) < 0) {
                error("Thread", "Could not creat thread");
            }
            */
        } else {
			printf("Error on connection: %s \n", strerror(errno));
		}
		Free(connfd);
    }
    pthread_mutex_destroy(&lock);
    printf("Good Bye!\n");
    exit(0);
}

void *thread_init(void *vargp) {
    Pthread_detach(pthread_self());
    while(1) {
        int clientfd = sbuf_remove(&sbuf);
        process_req(clientfd);
    }
}

/*
 * process_req - processes request from client and calls 
 * appropriate methods like GET.
 */
int process_req(int serverfd) {
    int is_static, port;
    char buf[MAXLINE], method[MAXLINE], uri[MAXLINE], version[MAXLINE];
    char filename[MAXLINE], cgiargs[MAXLINE];
    rio_t client;	

	/* Set client buffer */
    Rio_readinitb(&client, serverfd);
    
    /* Read Header */
    Rio_readlineb_w(&client, buf, MAXLINE);
    
    /* Initialize varible from header */
    sscanf(buf, "%s %s %s", method, uri, version);
    
    /* Break down the varibles to there nessary formats */    
    if((is_static = parse_uri(uri, filename, cgiargs, &port)) < 0) {
        warn("Parser", "Unable to parse URL");
    }

    /* Print Known header info */
    //printf("uri: %s\nhostname: %s\npathname: %s\n", uri, filename, cgiargs);
    //printf("Type: %s\nMethod: %s\nVersion: %s\nPort: %d\n\n", is_static ? "Static" : "Dynamic", method, version, port);

    if (strcmp(method, "GET") == 0 || strcmp(method, "POST") == 0) {                        
        handle_GET(client, serverfd, cgiargs, uri, filename, method, version, port);
    } else {
        warn("Method", "Unhandled method");
    }
	Close(serverfd); 
    return 0;
}

/* Connect to a server with a GET request, if aok send payload to client */
void handle_GET(rio_t client, int serverfd, char* cgiargs, char* uri, char* filename, char* method, char* version, int port) {
    int clientfd, status, contentlength;
    rio_t server;
    struct sockaddr_in sockaddr;
    socklen_t addrlen = sizeof(sockaddr);
    char logstring[MAXLINE], encoding[64];

    if((clientfd = open_clientfd_ts(filename, port)) < 0) {
        error("Clinet", "Unable to connect to client");
        Close(clientfd);
		return;
    }
    
    Rio_readinitb(&server, serverfd);
    send_GET(&client, clientfd, cgiargs, filename, method, version, port);
    
    Rio_readinitb(&server, clientfd);
    send_header(&server, serverfd, &status, &contentlength, encoding);
    
    // Log file    
    pthread_mutex_init(&lock, NULL);
    if (getpeername(clientfd,(struct sockaddr *)&sockaddr,&addrlen) < 0){
        error("Peername", "Error status");
    }
    format_log_entry(logstring, &sockaddr, uri, contentlength);
    logWrite(logstring);
    pthread_mutex_destroy(&lock);

    if(status == 404) {
        error("404", "File Not Found");
    } else if(status == 400) {
        error("400", "Bad Syntax");
    } else 
        send_payLoad(&server, serverfd, contentlength, encoding);
}

/* GET from server */
void send_GET(rio_t *client, int serverfd, char* path, char* filename, char* method, char* version, int port) {
   char buf[MAXLINE];
   int n;

   sprintf(buf, "GET /%s %s\r\n", path, version);
   Rio_writen_w(serverfd, buf, strlen(buf));
       
   while(strcmp(buf, "\r\n") != 0){
        if((n = Rio_readlineb_w(client, buf, MAXLINE)) == 0) {
            warn("Read", "Warning Reading faild");
            return;
        }
        
        if(!strncmp(buf, "Connection", 10)) {
            sprintf(buf, "Connection: close\r\n");
            n = strlen(buf);
        }
        else if(!strncmp(buf, "Proxy-Connection", 16)) {
            sprintf(buf, "Proxy-Connection: close\r\n");
            n = strlen(buf);
        }

        Rio_writen_w(serverfd,buf,n);
        //Fputs(buf, stdout);
    }

    Rio_writen_w(serverfd, "\r\n", 2);
}

/* Get header from server and send to client */
void send_header(rio_t *server, int serverfd, int *status, int *contentlength, char *encoding) {
    char buf[MAXLINE];
    int n;

    strcpy(buf, "\0");

    while((n = Rio_readlineb_w(server, buf, MAXLINE)) > 0) {
        if(strcmp(buf, "\r\n") != 0) {
            Rio_writen_w(serverfd, buf, n);
            break;
        }

        /* No Cashing */ 
        if(strstr(buf, "Cache-Control:") != 0)
            sprintf(buf, "%s", "Cache-Control: no-cache\r\n");

        Rio_writen_w(serverfd, buf, n);
     
        /* Save the nessasary variables */          
        sscanf(buf, "HTTP/1.1 %d", status);
        sscanf(buf, "Content-Length: %d ", contentlength);
        sscanf(buf, "Transfer-Encoding: %s", encoding);
           
        //Fputs(buf, stdout);
    }
}

/* send_payLoad recieves from server and sends it on to client */
void send_payLoad(rio_t *server, int serverfd, int contentlength, char *encoding) {
    char buf[MAXLINE];
    int n, size = MIN(MAXLINE, contentlength); 

    strcpy(buf, "\0");
    
    while((n = Rio_readlineb_w(server, buf, size)) > 0) {
        Rio_writen_w(serverfd, buf, n);
    }
}

/*
int open_clientfd_ts(char* hostname, int port) 
{
    int clientfd;

    if((clientfd = Open_clientfd(hostname, port)) < 0) {
        error("Connect", "Failed to Connect to client");
    }

    return clientfd;
}*/

/* open_clientfd_ts opens a socket and returns a connection to a client */
int open_clientfd_ts(char* hostname, int port) {
    int clientfd;
    struct sockaddr_in serveraddr;
    struct hostent *hp;
    
    if ((clientfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        return -1;
    }

    if ((hp = gethostbyname(hostname)) == NULL) {
        return -2;
    }

    bzero((char *) &serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    bcopy((char *) hp->h_addr, (char *) &serveraddr.sin_addr.s_addr, hp->h_length);
    serveraddr.sin_port = htons(port);
    
    if (connect(clientfd, (SA *)&serveraddr, sizeof(serveraddr)) < 0) {
        return -1;
    }

    printf("Connected to: %s\n", hp->h_name);

    return clientfd;
}

/*
 * parse_uri - URI parser
 * 
 * Given a URI from an HTTP proxy GET request (i.e., a URL), extract
 * the host name, path name, and port.  The memory for hostname and
 * pathname must already be allocated and should be at least MAXLINE
 * bytes. Return -1 if there are any problems.
 */
int parse_uri(char *uri, char *hostname, char *pathname, int *port) {
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
    *port = 80; /* default */
    
    if (*hostend == ':') {
	    *port = atoi(hostend + 1);
    }

    /* Extract the path */
    pathbegin = strchr(hostbegin, '/');
    
    if (pathbegin == NULL) {
	    pathname[0] = '\0';
    } else {
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
void format_log_entry(char *logstring, struct sockaddr_in *sockaddr, char *uri, int size) {
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

/* to_ip parses the IP address to a dotted decimal form */
char* to_ip(int ip, char* buf) {
	unsigned char bytes[4];

    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;
	sprintf(buf, "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);
	
	return buf;
}

/* Threadsafe wrapper for rio_readn */
ssize_t Rio_readn_w(int fd, void *ptr, size_t nbytes) {
    ssize_t n;
    
    if((n = rio_readn(fd, ptr, nbytes)) < 0) {
        error("read error", "rio_readn_w failed to read.");
        return 0;
    }

    return n;
}

/* Threadsafe wrapper for rio_writen */
void Rio_writen_w(int fd, void *usrbuf, size_t n) {    
    if(rio_writen(fd, usrbuf, n) != n) {
        error("write error", "rio_writen_w failed to write.");
        //return;
    }
}

/* Treadsafe wrapper for rio_readlineb */
ssize_t Rio_readlineb_w(rio_t *rp, void *usrbuf, size_t maxlen) {
    ssize_t rc;
    
    if((rc = rio_readlineb(rp, usrbuf, maxlen)) < 0) {
        error("readline error", "rio_readlineb_w failed to read.");
        return 0;
    }

    return rc;
}

/* write to the log file */
void logWrite(char * toLog) {
    //printf("Writing %s to file\n", toLog);
    FILE *l_file = fopen("proxy.log", "a");
    if (l_file == NULL) {
        error("Opening file", "Log file");
        exit(1);
    }
    fprintf(l_file, "%s\n", toLog);
    fclose(l_file);
}

/* printer function for warnings, warnings are printed in yellow */
void warn(char* code, char* warn) {
    printf(YELLOW);
    printf("%s: %s", code, warn);
    printf(RESET "\n"); 
}

/* printer function for errors, errors are printed in red */
void error(char* code, char* error) {
    printf(RED);
    printf("%s: %s", code, error);
    printf(RESET "\n");
}

/* Create an empty, bounded, shared FIFO buffer with n slots */
void sbuf_init(sbuf_t *sp, int n) {
    sp->buf = Calloc(n, sizeof(int));
    sp->n = n;
    /* Buffer holds max of n items */
    sp->front = sp->rear = 0;
    /* Empty buffer iff front == rear */
    Sem_init(&sp->mutex, 0, 1);
    /* Binary semaphore for locking */
    Sem_init(&sp->slots, 0, n);
    /* Initially, buf has n empty slots */
    Sem_init(&sp->items, 0, 0);
    /* Initially, buf has zero data items */
}

/* Clean up buffer sp */
void sbuf_deinit(sbuf_t *sp) {
    Free(sp->buf);
}

/* Insert item onto the rear of shared buffer sp */
void sbuf_insert(sbuf_t *sp, int item) {
    P(&sp->slots);
    /* Wait for available slot */
    P(&sp->mutex);
    /* Lock the buffer */
    sp->buf[(++sp->rear)%(sp->n)] = item;
    /* Insert the item */
    V(&sp->mutex);
    /* Unlock the buffer */
    V(&sp->items);
    /* Announce available item */
}

/* Remove and return the first item from buffer sp */
int sbuf_remove(sbuf_t *sp) {
    int item;
    P(&sp->items);
    /* Wait for available item */
    P(&sp->mutex);
    /* Lock the buffer */
    item = sp->buf[(++sp->front)%(sp->n)]; /* Remove the item */
    V(&sp->mutex);
    /* Unlock the buffer */
    V(&sp->slots);
    /* Announce available slot */
    return item;
}
