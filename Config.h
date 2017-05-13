#ifndef DNS_CONFIG_H
#define DNS_CONFIG_H

//
// C++ standard and STL
//
#include <cassert>
#include <iostream>
#include <sstream>
#include <cstring>
#include <string>
#include <vector>
#include <list>
#include <map>

#if defined(_WIN32)
#	include <stdint.h>
#	include <algorithm>
#   include <process.h>
#   include <winsock2.h>
#   include <ws2tcpip.h>
#   pragma comment(lib, "ws2_32.lib")
typedef int ssize_t;
typedef int socklen_t;
#else
#	include <ifaddrs.h>
#   include <fcntl.h>
#   include <pthread.h>
#   include <netdb.h>
#   include <errno.h>
#   include <sys/types.h>
#   include <unistd.h>
#	include <sys/ioctl.h>
#   include <sys/poll.h>
#   include <sys/types.h>
#   include <sys/socket.h>
#   include <netdb.h>
#   include <netinet/tcp.h>
#   include <netinet/in.h>
#   include <arpa/inet.h>
#endif

#ifndef _WIN32
#   define SOCKET 			int
#   define INVALID_SOCKET	-1
#endif

// Network
#define NETWORK_BEGIN   namespace network   {
#define DNS_BEGIN 	    namespace dns       {
#define DNS_END   	    }
#define NETWORK_END     }
#define DNS_TYPE_A      1
#define DNS_CLASS_IN	1

// Header
#define HEADER_LENGTH 12
#define DNS_RESPONSE_NO_ERROR			0
#define DNS_RESPONSE_FORMAT_ERROR 		1
#define DNS_RESPONSE_SERVER_FAILURE		2
#define DNS_RESPONSE_NAME_ERROR			3
#define DNS_RESPONSE_NOT_IMPLEMENTED	4
#define DNS_RESPONSE_REFUSED			5

// Resolver
#define DEFAULT_DNS_HOST    	"114.114.114.114"
#define DEFAULT_DNS_PORT    	53
#define DEFAULT_RETRY_TIMES 	10
#define DEFAULT_SOCKET_TIMEOUT	200 // ms
#define MAX_DNS_PACKET_SIZE 	512

#endif