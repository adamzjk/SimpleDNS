#include "DnsServer.h"

dns::Question::Question(const std::string& qname, unsigned short qtype)
: m_name(qname)
, m_type(qtype)
, m_class(DNS_CLASS_IN)
{

}

dns::Question::Question(const dns::Name& qname, unsigned short qtype, unsigned short qclass)
: m_name(qname)
, m_type(qtype)
, m_class(qclass)
{
    
}

dns::Question::~Question()
{
    
}

std::string dns::Question::toString()
{
    std::ostringstream oss;
    oss << "Question: " << m_name.toString() << " " << m_type << " " << m_class;
    return oss.str();
}

int dns::Question::toBuffer(unsigned char *buf, size_t size)
{   
    int nLen = -1;
    
    // Encode name
    nLen = m_name.toBuffer(buf, size);
    if (nLen <= 0)
    {
        //Error
    }
    else
    {
        // Copy type and class
        *(uint16_t*)(buf + nLen) = htons(m_type);
        nLen += 2;
        *(uint16_t*)(buf + nLen) = htons(m_class);
        nLen += 2;
    }
    
    return nLen;
}

// From buffer
dns::Question* dns::Question::fromBuffer(unsigned char* buf, size_t size, size_t &offset)
{
    dns::Question* question = NULL;
    
    //Parse name first
    dns::Name name;
    if (!name.fromBuffer(buf, size, offset))
    {
        //Error log
    }
    else
    {
        // type and class
        if (size - offset >= 4)
        {
            unsigned short qtype = ntohs(*(uint16_t*)(buf + offset));
            offset += 2;
            unsigned short qclass = ntohs(*(uint16_t*)(buf + offset));
            offset += 2;
            question = new dns::Question(name, qtype, qclass);
        }
    }
    
    return question;
}



