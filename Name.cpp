#include "DnsServer.h"

const char* dns::Name::s_szValidChars = "0123456789abcdefghijklmnopqrstuvwxyz-_/.";

dns::Name::Name() : m_length(0) {}

dns::Name::Name(const char* name) : m_length(0)
{
    std::string sName(name);
    parse(sName);
}

dns::Name::Name(std::string name)
: m_length(0) { parse(name); }

dns::Name::Name(const dns::Name* name)
: m_length(name->m_length)
{    
    for (std::list<std::string>::const_iterator it = name->m_parts.begin(); it != name->m_parts.end(); ++it)
    {
        m_parts.push_back(std::string(*it));
    }
}

// Parse a dot-divided rr_name   string -> m_parts
void dns::Name::parse(std::string& name)
{
    try
    {
        //Validate the rr_name first
        std::string sName = name;
        std::transform(sName.begin(), sName.end(), sName.begin(), ::tolower);
        if (sName.size() > 255)
        {
            std::cout << "error of tooooo loooog name";
        }
        else if (std::string::npos != sName.find_first_not_of(s_szValidChars, 0))
        {
            std::cout << "error of invalid characters";
        }
        else
        {
            // Divided domain into parts
            m_length = name.length() + 1; // \0 is another byte
            if (name.length() > 0 && name != "")
            {
                size_t last = name.rfind(".");
                if (std::string::npos == last || (name.length() - 1) != last)
                {
                    name.append("."); // add . in the end
                    ++m_length;
                }
            }
            
            size_t index = 0, pos;
            while ((pos = name.find_first_of(".", index)) != std::string::npos)
            {
                std::string part;
                part.append(name, index, pos - index); // . is not included
                m_parts.push_back(part);
                index = pos + 1;
            }
        }
    }
    catch (...)
    {
        std::cout << "some error";
    }
}

// Decode domain rr_name into a string lsit
// and create a new Name instance
bool dns::Name::fromBuffer(unsigned char* buf, size_t size, size_t& offset)
{
    return decode(buf, size, offset, m_parts, m_length);
}

//
// Recursively decode the rr_name in DNS packet
// One byte followed by string
// if two high bits are 00, then the rest 6 bits is the length of following string (0-63).
// if two high bits are 11, then the rest 6 bits and the following one byte is a pointer 
// value of pointer is the offset from header
// 
bool dns::Name::decode(unsigned char* buf, size_t size, size_t &offset,std::list<std::string>& results, size_t &len)
{
    bool no_error = true;

    for ( ; ; ) {
        if (offset >= size) {//beyond buffer
            no_error = false;
            break;
        }

        unsigned char next_length = buf[offset++];

        // '/0' is the termination
        if (next_length == 0) {
            break;
        }

        if (next_length > 63) { // pointer!
            if (next_length < 192 || offset == size) {
                // pointer error
                no_error = false;
                break;
            }
            size_t jump_to = (size_t) ((next_length & 63) << 8) + buf[offset++];
            if (!decode(buf, size, jump_to, results, len)) {
                // Some error occurs ..
                no_error = false;
            }
            break;
        }

        // normal situation
        len += next_length + 1; // plus "\0"
        std::string one_result;
        one_result.reserve(next_length); // prepare some space
        for (; next_length > 0; --next_length, ++offset)
            one_result.append(1, (char) tolower(buf[offset])); // save result
        results.push_back(one_result); // put into final result set
    }
    return no_error;
}

// Encode domain rr_name into a buffer
// Multiple sections, character number followed by the characters in each section
int dns::Name::toBuffer(unsigned char* buf, size_t size)
{
    int filled_length = -1;
    
    if (size >= m_length)
    {
        filled_length = 0;
        for (std::list<std::string>::iterator it = m_parts.begin(); it != m_parts.end(); ++it)
        {
            std::string& p = *it;
            if (0 < p.size() && p != ".")
            {
                //Length and following string
                buf[filled_length++] = (unsigned char) p.length();
                for (unsigned int j = 0; j < p.length(); ++j) // write into buffer
                {
                    buf[filled_length++] = (unsigned char) tolower(p.at(j));
                }
            }
        }
        // Termination
        buf[filled_length++] = 0;
    }
    return filled_length;
}

std::string dns::Name::toString()
{
    std::ostringstream oss;
    for(std::list<std::string>::iterator it = m_parts.begin(); it != m_parts.end(); ++it)
    {
        oss << *it << ".";
    }
    
    return oss.str();
}
