// dnf install glibc-devel.i686
// gcc -m32 gw.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stddef.h>
#include <signal.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

// Never used
void decrypt_ssl() {
    puts("TOP SECRET - DO NOT INVESTIGATE - GW-CLEARANCE NEEDED");
    puts("DO NOT REMOVE THESE MESSAGES FOR SECURITY REASONS");
    puts("NOT YET IMPLEMENTED");
    return;
}

int find(char *str, int startPos, int strLen, char *subStr, int subStrLen) {
    /**********************************************************************
    * BUG: This should be `pos < strLen-subStrLen`, otherwise we are      *
    * searching past the string end. Should not affect the results though *
    **********************************************************************/
    for (int pos=startPos; pos<strLen; pos++) {
        int match = 1;
        for (int i=0; i<subStrLen; i++) {
            if (str[pos+i] != subStr[i]) {
                match = 0;
                break;
            }
        }
        if (match) return pos;
    }
    return 0;
}

void filter_message(char *src, size_t len, char *dest) {
    char buf[1024];             // esp+0x00C ebp-0x41C
    struct sockaddr_in addr;    // esp+0x40C ebp-0x01C
    int fd;                     // esp+0x41C ebp-0x00C
    
    // filter_message+0x0022
    printf("[+] FILTERING MESSAGE: %s\n", src);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("0.0.0.0");
    addr.sin_port = htons(6666);
    // filter_message+0x0062
    fd = socket(AF_INET, SOCK_STREAM, SOL_IP);
    // filter_message+0x007a
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr))) {
        puts("[-] FILTER SERVER CONNECTION FAILED\n");
    } else {
        // filter_message+0x00a6
        send(fd, src, len, 0);
        // filter_message+0x00bd
        read(fd, dest, len * 2);
        close(fd);
        // filter_message+0x00e0
        printf("[+] FILTERED MESSAGE: %s\n", dest);
        /*****************************************************************
        * KEY BUG: message can be way over 1024 bytes, overflowing the   *
        * return address. Note that this copies the original, unfiltered *
        * output - and `buf` is not used for anything else.              *
        *****************************************************************/
        // filter_message+0x00f8
        memcpy(buf, src, len);
    }
    // *filter_message+261
}

void send_http_response(int fd, char *strHttpCode, char *text) {
    char headerTmpl[107] = "HTTP/1.1 %s\r\n"
                           "Server: %s\r\n"
                           "Content-Length: %s\r\n"
                           "Connection: close\r\n"
                           "Content-Type: text/html; charset=UTF-8\r\n"
                           "\r\n";
    char strServerName[10] = "GW SERVER";
    char contentTmpl[70] = "<html><head><title>GW</title></head><body><pre>%s</pre></body></html>";
    char strContentLength[20];

    // Calculate content length (template + param)
    int contentLen = strlen(contentTmpl) + strlen(text);
    // Only now we can create the string for Content-Length
    sprintf(strContentLength, "%d", contentLen);
    // And only now we can calculate complete header length
    int headerLen = strlen(headerTmpl) + strlen(strHttpCode) + strlen(strServerName) + strlen(strContentLength);
    // And full response length
    int responseLen = headerLen + contentLen;
    // Craft the full response
    char *responseBuf = (char *)malloc(responseLen);
    sprintf(responseBuf, headerTmpl, strHttpCode, strServerName, strContentLength);
    sprintf(responseBuf + headerLen, contentTmpl, text);
    // And send it
    send(fd, responseBuf, responseLen, 0);
    free(responseBuf);
}

void send_http_error(int fd, char *text) {
    printf("[-] ERROR: %s\n", text);
    send_http_response(fd, "400 Bad Request", text);
}

void connection_handler(int fd) {
    // *connection_handler+29
    puts("[+] SUCCESSFULLY CREATED NEW CLIENT THREAD");

    // *connection_handler+45
    char *recvBuf = (char*)malloc(10240);
    // *connection_handler+70
    read(fd, recvBuf, 10240);  // +75
    // *connection_handler+91
    printf("[+] RECIEVED: %s\n", recvBuf);

    // Request must have "\r\n\r\n"
    // *connection_handler+121
    if (!find(recvBuf, 0, 10240, "\r\n\r\n", 4)) {
        send_http_error(fd, "Error no \\r\\n\\r\\n recieved!"); return;
    }

    // Request must have "Host: "
    // *connection_handler+186
    int hostHeaderPos = find(recvBuf, 0, 10240, "Host: ", 6);
    if (!hostHeaderPos) {
        send_http_error(fd, "Error no \"Host: \" recieved!"); return;
    }

    // There must be "\r\n" after "Host: "
    // *connection_handler+256
    int crLfAfterHostPos = find(recvBuf, hostHeaderPos + 6, 10240, "\r\n", 2);
    if (!crLfAfterHostPos) {
        send_http_error(fd, "Error no \"Host: \" end (\\r\\n) recieved!"); return;
    }

    // String after "Host: " must be not empty
    // *connection_handler+299
    unsigned int hostLen = crLfAfterHostPos - hostHeaderPos - 6;
    if ((hostLen == 0) || (hostLen>100)) {
        send_http_error(fd, "Invalid Host Field Size!"); return;
    }

    // Parse "Host:" header and resolve it into IP/port.
    /**************************************************************************
    * BUG: if there is no port, hostBuf and hostBufHostOnly will be one byte  *
    * too small. It will most often work, but this pattern is repeated in few *
    * other parts of code below and leads to garbage after hostname, failures *
    * to resolve it, etc.                                                     *
    **************************************************************************/
    // *connection_handler+355
    char *hostBuf = (char*)malloc(hostLen);             // name.or.ip:port              0xf7402de0
    // *connection_handler+372
    char *hostBufHostOnly = (char*)malloc(hostLen);     // name.or.ip                   0xf7402df0
    // *connection_handler+396
    char *hostBufPortOnly = (char*)malloc(hostLen);     // port                         0xf7402e00
    // *connection_handler+412
    char *ipAddrString = (char*)malloc(50);             // INET6_ADDRSTRLEN = 46        0xf7402e10
    int port = 80;
    
    // *connection_handler+444
    memcpy(hostBuf, &recvBuf[hostHeaderPos + 6], hostLen);
    /***********************************************
    * BUG: This may print extra garbage, see above *
    ***********************************************/
    // *connection_handler+465
    printf("[+] HOST: %s\n", hostBuf);
    
    // *connection_handler+493
    int colonPos = find(hostBuf, 0, hostLen, ":", 1);
    // *connection_handler+508
    if (colonPos) {
        // *connection_handler+522
        memcpy(hostBufHostOnly, hostBuf, colonPos);
        // *connection_handler+558
        memcpy(hostBufPortOnly, &hostBuf[colonPos + 1], hostLen - colonPos + 1);  // +1 because atoi below
        // *connection_handler+572
        port = atoi(hostBufPortOnly);
        // *connection_handler+599
        printf("[+] HOSTNAME: %s\n[+] PORT CHARS: %s\n[+] PORT: %d\n", hostBufHostOnly, hostBufPortOnly, port);
    } else {
        // *connection_handler+621
        memcpy(hostBufHostOnly, hostBuf, hostLen);
    }

    /****************************************************************
    * BUG: gethostbyname will fail unless we're lucky and have a \0 *
    * (or spaces followed by \0) after hostBufHostOnly.             *
    ****************************************************************/
    // *connection_handler+635
    struct hostent *host = gethostbyname(hostBufHostOnly);                           // 0xf7f40970
    if (!host) {
        send_http_error(fd, "Failed resolving hostname!"); return;
    }
    // connection_handler+0x02a6
    struct in_addr **addrList = (struct in_addr **)host->h_addr_list;
    for (int i = 0; addrList[i] != NULL; i++) {
        /******************************************************************
        * POSSIBLE LEAK: `inet_ntoa` returns a buffer in the glibc data   *
        * segment, which can be used to calculate the libc offset. We can *
        * not intercept it directly here, but this buffer contains some   *
        * additional offsets and it is freed later.                       *
        * One attack vector would be to craft a malloc()/free() sequence  *
        * where that data will be allocated to something that is returned *
        * to the user. One problem: these results might be subject to the *
        * "filter", so, need to avoid having zeros here.                  *
        ******************************************************************/
        // *connection_handler+718
        char *inetNToAResult = inet_ntoa(*addrList[i]);                           // 0xf7d65b1c
        // *connection_handler+735
        memcpy(ipAddrString, inetNToAResult, 50);
    }
    // *connection_handler+781
    printf("[+] IP: %s\n", ipAddrString);

    // *connection_handler+797
    char *proxyRequestBuf = (char*)malloc(10240);                                 // 0xf7404570
    
    // *connection_handler+830
    int crLfAfterGetPos = find(recvBuf, 0, 10240, "\r\n", 2);
    if (!crLfAfterGetPos) {
        send_http_error(fd, "First Line not found!"); return;
    }

    // Grab fist request line.
    /***********************************************************************
    * BUG: missing \0 again. Also, not sure what's the point of doing this *
    * with an additional buffer, the only outcome is `httpPos`. Perhaps    *
    * another attack vector?                                               *
    ***********************************************************************/
    // *connection_handler+879
    char *proxyRequestBufFirstLine = (char*)malloc(crLfAfterGetPos);               // 0xf7406d80
    // *connection_handler+902
    memcpy(proxyRequestBufFirstLine, recvBuf, crLfAfterGetPos);
    /******************************************************
    * BUG: this can scan past `proxyRequestBufFirstLine`. *
    ******************************************************/
    // *connection_handler+932
    int httpPos = find(proxyRequestBufFirstLine, 0, 10240, "http://", 7);
    if (!httpPos) {
        send_http_error(fd, "Did not found http:// in the first request line!"); return;
    }
    // *connection_handler+981
    free(proxyRequestBufFirstLine);
    proxyRequestBufFirstLine = NULL;  // Nice, no UAF :)



    // *connection_handler+1018
    /********************************************************************
    * BUG: this will succeed if space is *anywhere* in the request, not *
    * just in the first line                                            *
    ********************************************************************/
    int spacePos = find(recvBuf, 0, 10240, " ", 1);
    if (!spacePos) {
        send_http_error(fd, "Did not find a space in the first line!"); return;
    }
    
    // *connection_handler+1088
    int urlPathPos = find(recvBuf, httpPos + 7, 10240, "/", 1);
    if (!urlPathPos) {
        send_http_error(fd, "Did not find a slash (/) in the first line!"); return;
    }
    // recvBuf:   "GET http://name.or.ip:port/someurl\r\n.*"   (or without :port)
    // proxyRequestBuf:    "GET /someurl\r\n.*"
    // *connection_handler+1147
    memcpy(proxyRequestBuf, recvBuf, spacePos + 1);
    // *connection_handler+1188
    memcpy(proxyRequestBuf + spacePos + 1, &recvBuf[urlPathPos], 10240 - urlPathPos); // Everything from /path
    // *connection_handler+1209
    // Should be: "GET /...<and everything copied from here>"
    printf("[+] PROXY REQUEST: %s\n", proxyRequestBuf);

    // *connection_handler+1226
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sockaddr;
    sockaddr.sin_family = AF_INET;
    // *connection_handler+1252
    sockaddr.sin_addr.s_addr = inet_addr(ipAddrString);
    // *connection_handler+1276
    sockaddr.sin_port = htons(port);

    // Free all temp buffers.
    // *connection_handler+1297
    free(hostBuf); hostBuf = NULL;
    // *connection_handler+1311
    free(hostBufHostOnly); hostBufHostOnly = NULL;
    // *connection_handler+1322
    free(hostBufPortOnly); hostBufPortOnly = NULL;
    // *connection_handler+1339
    free(ipAddrString); ipAddrString = NULL;

    // Connect to target host and send the entire "Host: /someurl..." message.
    // *connection_handler+1391
    if (connect(sockfd, (struct sockaddr*)&sockaddr, sizeof(sockaddr))) {
        puts("[-] PROXY CONNECTION FAILED\n"); return;
    }

    /********************************************************************
    * BUG: OK, this is terrible :-) it sends all the crap in the buffer *
    * after the initial (proper) response. This is why we usually get a *
    * second response with a 400.                                       *
    ********************************************************************/
    // *connection_handler+1440
    send(sockfd, proxyRequestBuf, 10240, 0);
    // *connection_handler+1454
    free(proxyRequestBuf); proxyRequestBuf = NULL;

    // Retrieve answer from the target host
    /*********************************************************************
    * BUG: this is likely the same memory as `proxyRequestBuf` - and it  *
    * might still have non-zero contents. We're likely to see garbage in *
    * output. Could be another attack vector?                            *
    *********************************************************************/
    // connection_handler+1477
    char *proxyAnswerBuf = (char*)malloc(10240);
    /*************************************************************************
    * BUG: this fails if the response comes in more than one chunk. Could be *
    * e.g. headers first, or a large, fragmented request. Also this does not *
    * really check the contents, it does not have to be HTTP at all.         *
    *************************************************************************/
    // connection_handler+1502
    read(sockfd, proxyAnswerBuf, 10240);
    // *connection_handler+1523
    printf("[+] PROXY ANSWER: %s\n", proxyAnswerBuf);
    // Not sure what this is for. Perhaps to make some heap-based attacks
    // more difficult.
    // *connection_handler+1539
    void *UNUSED_BUF = malloc(10240);

    // *connection_handler+1572
    int messageBeginPos = find(proxyAnswerBuf, 0, 10240, "<message>", 9);
    // If the answer contains "<message>", do the  formatting / filtering
    if (messageBeginPos) {
        // *connection_handler+1615
        int messageEndPos = find(proxyAnswerBuf, 0, 10240, "</message>", 10);
        // It must contain </message> now, too.
        if (!messageBeginPos) {
            send_http_error(fd, "&lt;/message&gt; not found in answer!"); return;
        }
        // Print these positions
        // *connection_handler+1671
        printf("%d\n", messageEndPos);
        // *connection_handler+1692
        printf("%d\n", messageBeginPos);
        // *connection_handler+1700
        unsigned int messageLen = messageEndPos - messageBeginPos - 9;  // "<message>"
        // Check if empty or too long
        // *connection_handler+1712
        if ((messageLen == 0) || (messageLen > 4000) ) {
            send_http_error(fd, "Invalid Message Size!"); return;
        }
        // Now allocate space for proper string
        // *connection_handler+1763
        char *messageBuf = (char*)malloc(messageLen + 1);  // never freen
        // (although this still doesn't terminate it with \0...)
        // *connection_handler+1795
        memcpy(messageBuf, &proxyAnswerBuf[messageBeginPos + 9], messageLen);
        // Response will be filtered
        // *connection_handler+1812
        char *strResponse = (char*)malloc(2 * messageLen);   // never freed
        // *connection_handler+1836
        printf("size: %d\n", messageLen);
        // Do the filtering (see KEY BUG above!)
        // *connection_handler+1856
        filter_message(messageBuf, messageLen, strResponse);
        // Send filtered response to the proxy client
        // *connection_handler+1880
        send_http_response(fd, "200 OK", strResponse);
    } else {
        // Otherwise, just return it to the proxy client
        // *connection_handler+1904
        send(fd, proxyAnswerBuf, 10240, 0);
    }
    // *connection_handler+1918
    free(UNUSED_BUF);
    // *connection_handler+1932
    free(proxyAnswerBuf); proxyAnswerBuf = NULL;
    // *connection_handler+1953
    close(fd);
    // *connection_handler+1967
    free(recvBuf);
}


int main(void) {
    struct sockaddr_in bindAddr, acceptAddr;
    pthread_t thread;
    
    puts("STARTING GW TEST SYSTEM");
    signal(SIGPIPE, SIG_IGN);
    int sockfd = socket(AF_INET, SOCK_STREAM, SOL_IP);
    int sockopt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof(sockopt)) < 0) {
        puts("[-] SO_REUSEADDR FAILED");
    } else {
        int port = 8080;
        if (port == 443)
            decrypt_ssl();
        bindAddr.sin_family = AF_INET;
        bindAddr.sin_addr.s_addr = 0;
        bindAddr.sin_port = htons(8080);
        puts("[...] BINDING");
        int err = bind(sockfd, (struct sockaddr*)&bindAddr, sizeof(bindAddr));
        if (err < 0) {
            puts("[-] BINDING FAILED");
        } else {
            listen(sockfd, 3);
            puts("[...] LISTENING");
            do {            
                socklen_t acceptAddrLen = sizeof(acceptAddr);
                int fd = accept(sockfd,(struct sockaddr *)&acceptAddr,&acceptAddrLen);
                puts("[+] ACCEPTED CONNECTION");
                err = pthread_create(&thread, NULL, (void*)connection_handler, (void*)&fd);
            } while (err > -1);
            puts("[-] FAILED TO CREATE THREAD");
        }
    }
    return 1;
}
