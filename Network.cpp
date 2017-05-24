#include <cassert>
#include <iostream>
#include <sstream>
#include "DnsServer.h"

NETWORK_BEGIN

// for win32 only
bool startup()
{
#ifdef _WIN32
	WORD wVersionRequested = MAKEWORD(2, 2); //MAKEWORD(lowbyte, highbyte)
    WSADATA wsaData;
    int err = WSAStartup(wVersionRequested, &wsaData);
    if (err != 0)
	{
        printf("WSAStartup failed with error: %d\n", err);
        return false;
    }
    
    if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2)
	{
        printf("Could not find a usable version of Winsock.dll\n");
        WSACleanup();
        return false;
    }
#endif
    return true;
}

void cleanup()
{
#ifdef _WIN32
	WSACleanup();
#endif
}

// return host ip address
struct in_addr resolveHostName(const std::string& name)
{
    int retry = 5;
    struct addrinfo* info = 0;
    struct addrinfo hints = { 0 };
    hints.ai_family = PF_INET;

    int rs = 0;
    do
    {
        rs = ::getaddrinfo(name.c_str(), 0, &hints, &info);
    }
    while(info == 0 && rs == EAI_AGAIN && --retry >= 0);
    
    if(rs != 0) // RETURN 0 = SUCCESS
    {
        assert(false);
    }
    
    sockaddr_in* sin = reinterpret_cast<sockaddr_in*>(info->ai_addr);
    in_addr ip = sin->sin_addr;
    freeaddrinfo(info);
    
    return ip;
}

UdpSocket::UdpSocket()
{
    memset(&_sin, 0, sizeof(_sin));
	_sin.sin_family = AF_INET;

    _socket = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	assert(_socket != INVALID_SOCKET);
}

UdpSocket::UdpSocket(const std::string& host, unsigned short port)
{
    memset(&_sin, 0, sizeof(_sin));
	_sin.sin_family = AF_INET;
	_sin.sin_port = htons(port);
	_sin.sin_addr.s_addr = resolveHostName(host).s_addr;
 
    _socket = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	assert(_socket != INVALID_SOCKET);
}

UdpSocket::~UdpSocket()
{
#if defined(_WIN32)
    int error = WSAGetLastError();
    closesocket(_socket);
    WSASetLastError(error);
#else
    int error = errno;
    close(_socket);
    errno = error;
#endif
}

// send! return size of sent
ssize_t UdpSocket::write(const unsigned char* buf, size_t size)
{
	return ::sendto(_socket, buf, size, 0, (struct sockaddr*)&_sin, sizeof(_sin));
}

// read from buffer
ssize_t UdpSocket::read(unsigned char* buf, size_t size, int timeout)
{
    struct timeval tv;
    tv.tv_sec = timeout / 1000;
    tv.tv_usec = (timeout % 1000) * 1000;
	
	fd_set fds;
    FD_ZERO(&fds);
    FD_SET(_socket, &fds);
    
    int rc = ::select(sizeof(fds)*8, &fds, NULL, NULL, &tv);
    if(rc > 0 && FD_ISSET(_socket, &fds))
    {
	    struct sockaddr_in sin;
	    memset(&sin, 0, sizeof(sin));
	    socklen_t len = sizeof(sin);
		return ::recvfrom(_socket, buf, size, 0, (struct sockaddr*)&sin, &len);
	}
	
	return -1;
}

NETWORK_END
