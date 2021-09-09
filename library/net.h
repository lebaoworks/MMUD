#pragma once
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>

//Increase BUFSIZE can make net_forward_socket() crash in allocating stack memory
#define BUFSIZE 4096
#define DEFAULT_ADDR "127.0.0.1"
#define DEFAULT_PORT 4444

// Convert 4-byte ip address to dotted-string ip
void net_itoa(uint32_t ip, char buffer[16])
{
    memset(buffer, 0, 16);
    inet_ntop(AF_INET, &ip, buffer, INET_ADDRSTRLEN);
}

// Convert dotted-string ip address to 4-byte ip
uint32_t net_atoi(char* ip)
{
    uint32_t res;
    inet_pton(AF_INET, ip, &res);
    return res;
}

// Read until got n bytes or connection closed
int net_recvn(int fd, char *buf, int n)
{
    int nread, save = n;
    while (n > 0)
    {
        nread = recv(fd, buf, n, 0);
        if (nread == -1)
        {
            if (errno == EINTR || errno == EAGAIN)
                continue;
        }
        else
        {
            if (nread == 0)
                break;
            else
            {
                n -= nread;
                buf += nread;
            }
        }
    }
    return save-n;
}

// Write until wrote n bytes or connection closed
int net_sendn(int fd, char *buf, int n)
{
    int nwrite, save = n;
    while (n > 0)
    {
        nwrite = send(fd, buf, n, 0);
        if (nwrite == -1)
        {
            if (errno == EINTR || errno == EAGAIN)
                continue;
        }
        else
        {
            if (nwrite == 0)
                break;
            else
            {
                n -= nwrite;
                buf += nwrite;
            }
        }
    }
    return save-n;
}

// Connect to address:port
int net_tcp_connect(char* addr, unsigned short port)
{
    struct sockaddr_in remote;
    memset(&remote, 0, sizeof(struct sockaddr_in));
    remote.sin_family = AF_INET;
    remote.sin_addr.s_addr = net_atoi(addr);
    remote.sin_port = htons(port);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1)
        return -1;
    char _x = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &_x, sizeof(int));
    if (connect(fd, (struct sockaddr *)&remote, sizeof(struct sockaddr_in)) < 0)
    {
        close(fd);
        return -1;
    }
    return fd;
}

// Connect to address:port
int net_udp_connect(char* addr, unsigned short port)
{
    struct sockaddr_in remote;
    memset(&remote, 0, sizeof(struct sockaddr_in));
    remote.sin_family = AF_INET;
    remote.sin_addr.s_addr = net_atoi(addr);
    remote.sin_port = htons(port);

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1)
        return -1;
    char _x = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &_x, sizeof(int));
    if (connect(fd, (struct sockaddr *)&remote, sizeof(struct sockaddr_in)) < 0)
    {
        close(fd);
        return -1;
    }
    return fd;
}

// Run a tcp service
int net_tcp_server(char* addr, unsigned short port, void* handler, bool* halt)
{
    int sock = 0; 
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
        return -1; 

    struct sockaddr_in serv_addr; 
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_family = AF_INET; 
    serv_addr.sin_port = htons(port); 
    
    if (bind(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
        return 1; 
    if (listen(sock, 1) < 0)
        goto EXIT;
   
    int sock_client = 0;
    struct sockaddr_in client_addr;
    socklen_t addr_size = sizeof(client_addr);
    
    while (1)
    {
        if ((sock_client = accept(sock,(struct sockaddr *)&client_addr, &addr_size))<0)
            continue;
        //if create thread success
        ((void (*)(int, struct sockaddr_in*)) handler)(sock_client, &client_addr);
        close(sock_client);
    }
    //close connection
    close(sock);
    return 0;

    EXIT:
    close(sock);
    return 1;
}