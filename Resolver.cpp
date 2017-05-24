#include "DnsServer.h"

dns::Resolver::Resolver()
: m_socket(DEFAULT_DNS_HOST, DEFAULT_DNS_PORT) {}

dns::Resolver::Resolver(const char* host, unsigned short port)
: m_socket(host, port) {}

dns::Resolver::Resolver(const std::string& host, unsigned short port)
: m_socket(host, port) {}


bool dns::Resolver::resolve(const char* name, unsigned short type, dns::Message& response)
{
    std::string sName(name);
    return resolve(sName, type, response);
}


bool dns::Resolver::resolve(const std::string& name, unsigned short type, dns::Message& response)
{
    dns::Message query(name, type);
    return resolve(query, response);
}

/*
bool dns::Resolver::resolve(dns::Message& query, dns::Message& response)
{
    // Output request packet for debug
    //std::cout << query.toString();
    
    // Buffer for request packet
    unsigned char buf_out[MAX_DNS_PACKET_SIZE];
    int size_out = query.toBuffer(buf_out, MAX_DNS_PACKET_SIZE);
    if (size_out <= 0)
    {
        std::cout << "Query message encoding error." << std::endl;
        return false;
    }

    // Buffer for response packet
    unsigned char buf_in[MAX_DNS_PACKET_SIZE];
    size_t size_in = 0;
    
    // Retry to send until receive response packet
    bool bRet = false;
    for (int i = 0; i < DEFAULT_RETRY_TIMES; i++)
    {
        if (m_socket.write(buf_out, (size_t)size_out) <= 0)
        {
            std::cout << "Send query message error." << std::endl;
            continue;
        }
        
        size_in = (size_t) m_socket.read(buf_in, MAX_DNS_PACKET_SIZE, DEFAULT_SOCKET_TIMEOUT);
        if(size_in > 0 && response.fromBuffer(buf_in, size_in))
        {
            bRet = true;
            break;
        }
    }
    return bRet;
}*/

// !!!
bool dns::Resolver::resolve(dns::Message& query, dns::Message& response, unsigned char *buf, size_t *size)
{
    // Output request packet for debug
    //std::cout << query.toString();

    // 1, Make buffer for request packet
    unsigned char buf_out[MAX_DNS_PACKET_SIZE];
    int size_out = query.toBuffer(buf_out, MAX_DNS_PACKET_SIZE);
    if (size_out <= 0)
    {
        std::cout << "Query message encoding error." << std::endl;
        return false;
    }

    // 2, Prepare buffer for response packet
    unsigned char buf_in[MAX_DNS_PACKET_SIZE];
    size_t size_in = 0;

    // 3, Write - Sent - Read - Resolve
    bool bRet = false;
    for (int i = 0; i < DEFAULT_RETRY_TIMES; i++)
    {   // 3.1 Write & Sent
        if (m_socket.write(buf_out, (size_t)size_out) <= 0)
        {
            std::cout << "Send query message error." << std::endl;
            continue;
        }

        // 3.2 Read & Resolve
        size_in = (size_t) m_socket.read(buf_in, MAX_DNS_PACKET_SIZE, DEFAULT_SOCKET_TIMEOUT);
        if(size_in > 0 && response.fromBuffer(buf_in, size_in))
        {
            if(buf) {
                assert(*size < size_in);
                memcpy(buf, buf_in, size_in);
                *size = size_in;
            }
            bRet = true;
            break;
        }
    }
    return bRet;
}
