#include "DnsServer.h"

DNS_BEGIN
	
ResourceRecord::ResourceRecord(unsigned short rtype, unsigned short rdlen)
: m_type(rtype)
, m_class(0)
, m_ttl(0)
, m_rdlen(rdlen) {}

std::string ResourceRecord::toString(int debug)
{
    std::ostringstream oss;
    if(debug)
    {
        std::cout << "Resource Record: "
                  << m_name.toString()
                  << " m_type:" << m_type
                  << " m_class:" << m_class
                  << " m_ttl:" << m_ttl
                  << " m_rdlen:" << m_rdlen;
    }
    struct in_addr ia = {htonl(m_ip)};
    std::string ip = inet_ntoa(ia);
    oss << ip;
    return oss.str();
}

// From buffer
bool ResourceRecord::fromBuffer(unsigned char* buf, size_t size, size_t &offset)
{
    // Header 
    if (m_name.fromBuffer(buf, size, offset))
    {       
        if (size - offset >= 10)
        {
            m_type = ntohs(*(uint16_t*)(buf + offset));
            offset += 2;
            m_class = ntohs(*(uint16_t*)(buf + offset));
            offset += 2;
            m_ttl = ntohl(*(uint32_t*)(buf + offset));
            offset += 4;
            m_rdlen = ntohs(*(uint16_t*)(buf + offset));
            offset += 2;
            return dataFromBuffer(buf, size, offset);
        }
    }
    return false;
}

// Parse RDATA of A record
// RDATA is 4-bytes value of IPv4 address
    bool dns::ResourceRecord::dataFromBuffer(unsigned char* buf, size_t size, size_t& offset)
    {
        if(size - offset >= 4)
        {
            m_ip = ntohl(*(uint32_t *)(buf+offset));
            offset += 4;
            return true;
        }
        return false;
    }

DNS_END
