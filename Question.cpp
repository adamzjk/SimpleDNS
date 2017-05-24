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

std::string dns::Question::toString()
{
    std::ostringstream oss;
    oss << "Question: " << m_name.toString() << " " << m_type << " " << m_class;
    return oss.str();
}

int dns::Question::toBuffer(unsigned char *buf, size_t size)
{   
    int filled_length = -1;
    
    // Encode rr_name
    filled_length = m_name.toBuffer(buf, size);
    if (filled_length <= 0)
    {
        return -1;
    }
    else
    {
        // Copy type and class
        *(uint16_t*)(buf + filled_length) = htons(m_type);
        filled_length += 2;
        *(uint16_t*)(buf + filled_length) = htons(m_class);
        filled_length += 2;
    }
    
    return filled_length;
}

// From buffer
dns::Question* dns::Question::fromBuffer(unsigned char* buf, size_t size, size_t &offset)
{
    dns::Question* question = NULL;
    
    //Parse rr_name first
    dns::Name name;
    if (!name.fromBuffer(buf, size, offset))
    {
        return NULL;
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



