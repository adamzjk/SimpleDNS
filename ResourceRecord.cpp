#include "DnsServer.h"

DNS_BEGIN
	
ResourceRecord::ResourceRecord(unsigned short rtype, unsigned short rdlen)
: rr_type(rtype)
, rr_class(0)
, rr_ttl(0)
, rr_rdlen(rdlen) {}

std::string ResourceRecord::toString(int debug)
{
    std::ostringstream oss;
    if(debug)
    {
        std::cout << "Resource Record: "
                  << rr_name.toString()
                  << " rr_type:" << rr_type
                  << " rr_class:" << rr_class
                  << " rr_ttl:" << rr_ttl
                  << " rr_rdlen:" << rr_rdlen;
    }
    struct in_addr ia = {htonl(ip_addr)};
    std::string ip = inet_ntoa(ia);
    oss << ip;
    return oss.str();
}

// From buffer
bool ResourceRecord::fromBuffer(unsigned char* buf, size_t size, size_t &offset)
{
    // msg_header
    if (rr_name.fromBuffer(buf, size, offset))
    {       
        if (size - offset >= 10)
        {
            rr_type = ntohs(*(uint16_t*)(buf + offset));
            offset += 2;
            rr_class = ntohs(*(uint16_t*)(buf + offset));
            offset += 2;
            rr_ttl = ntohl(*(uint32_t*)(buf + offset));
            offset += 4;
            rr_rdlen = ntohs(*(uint16_t*)(buf + offset));
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
            ip_addr = ntohl(*(uint32_t *)(buf + offset));
            offset += 4;
            return true;
        }
        return false;
    }

DNS_END
