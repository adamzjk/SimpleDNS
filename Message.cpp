#include "DnsServer.h"

void dns::Message::clearList()
{
    // empty all questions and resource records
    for(std::list<dns::Question*>::iterator it = m_questions.begin(); it != m_questions.end(); ++it)
    {
        dns::Question* p = *it;
        if(p != NULL)
            delete p;
    }
    m_questions.clear();
    
    for(std::list<dns::ResourceRecord*>::iterator it = m_answers.begin(); it != m_answers.end(); ++it)
    {
        dns::ResourceRecord* p = *it;
        if(p != NULL)
            delete p;
    }
    m_answers.clear();
}

void dns::Message::addQuestion(const std::string& qname, unsigned short qtype)
{
	m_header.idset();
	m_header.rdset(true); // set question = True
	
	dns::Question* question = new dns::Question(qname, qtype);
	m_questions.push_back(question);
	m_header.qdinc();
}

// Encode a request packet to buffer
int dns::Message::toBuffer(unsigned char *buf, size_t size)
{
    assert(!header().qr()); // assert it is a query
    int filled_size = -1;
    memset(buf, 0, size);
    
    // Header
    filled_size = m_header.toBuffer(buf, size);
    if (filled_size <= 0)
    {
        std::cout << "Encoding header error." << std::endl;
    }
    else
    {        
        size -= filled_size;
        buf += filled_size; // slide
    
        // Questions
        for (std::list<dns::Question*>::iterator it = m_questions.begin(); it != m_questions.end(); ++it) 
        {
            int nLen = (*it)->toBuffer(buf, size);
            
            if(nLen <= 0)
            {
                std::cout << "Encoding question error. " << std::endl; 
            }
            else
                filled_size += nLen;
                buf += nLen;
        }
    }
    return filled_size; // return filled size of the buffer
}

// Decode a response packet
bool dns::Message::fromBuffer(unsigned char* buf, size_t size)
{
    bool bRet = true;
    size_t offset = 0;
        
    if (!m_header.fromBuffer(buf, size, offset))
    {
        std::cout << "Decode header error, offset: " << offset << std::endl;
        bRet = false;
    }
    else
    {
        // Question and answers pointer is relative to the end of header
        clearList();
        
        // questions
        for (int i = 0; bRet && i < m_header.qdcount(); ++i)
        {
            dns::Question* question = dns::Question::fromBuffer(buf, size, offset);
            if (question == NULL)
            {
                std::cout << "Decode question error, offset: " << offset << std::endl;
                bRet = false;
            }
            else
                m_questions.push_back(question);
        }
        
        // answers
        for (int i = 0; bRet && i < m_header.ancount(); ++i)
        {
            //dns::ResourceRecord* rr = dns::RRFactory::fromBuffer(buf, size, offset);
            ResourceRecord* rr = new ResourceRecord(DNS_TYPE_A);
            if (!rr->fromBuffer(buf, size, offset))
            {
                std::cout << "Decode answer error, offset: " << offset << std::endl;
                bRet = false;
            }
            else
                m_answers.push_back(rr);
        }
        
        // In this implementation, we did not parse sections of authority and additional
        // so some data may be left in the buffer
        //assert(offset == size);
    }
    
    return bRet;
}

std::string dns::Message::toString()
{
    std::ostringstream oss;
    oss << m_header.toString() << std::endl;
    
    for(std::list<dns::Question*>::iterator it = m_questions.begin(); it != m_questions.end(); ++it)
    {
        dns::Question* q = *it;
        if(q != NULL)
            oss << q->toString() << std::endl;
    }
    
    for(std::list<dns::ResourceRecord*>::iterator it = m_answers.begin(); it != m_answers.end(); ++it)
    {
        dns::ResourceRecord* rr = *it;
        if(rr != NULL)
            oss << rr->toString() << std::endl;
    }
    
    return oss.str();
}

std::string dns::Message::getOneAddress() {
    std::ostringstream oss;
    std::list<dns::ResourceRecord*>::iterator it = m_answers.begin();
    dns::ResourceRecord* rr = *it;
    if(rr != NULL)
        oss << rr->toString(false) << std::endl;
    else
        oss << "No Address Returned!";
    return oss.str();
}




