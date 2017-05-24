//
// Created by AdamZJK on 13/05/2017.
//
#include "Config.h"

#ifndef DNS_DNSSERVER_H
#define DNS_DNSSERVER_H


NETWORK_BEGIN

    bool startup(); // for Win32
    void cleanup(); // for Win32

    struct in_addr resolveHostName(const std::string& name);

    class UdpSocket
    {
    public:
        UdpSocket();
        UdpSocket(const std::string& host, unsigned short port); // Remote address
        virtual ~UdpSocket();

        ssize_t write(const unsigned char* buf, size_t size);
        ssize_t read(unsigned char* buf, size_t size, int timeout);

    private:
        SOCKET _socket;
        sockaddr_in _sin;
    };
NETWORK_END


DNS_BEGIN

class Header
{
//    The header contains the following fields:
//
//            1  1  1  1  1  1
//    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |                      ID                       |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |                    QDCOUNT                    |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |                    ANCOUNT                    |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |                    NSCOUNT                    |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |                    ARCOUNT                    |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
public:
    Header();
    virtual ~Header();

    int toBuffer(unsigned char* buf, size_t size); // write domain rr_name into buffer
    bool fromBuffer(unsigned char* buf, size_t size, size_t& offset); // read domain rr_name from buffer
    std::string toString(); // to std::string
    unsigned short idset(unsigned short id = 0); // assign an ID

    void rdset(bool rd)         { m_flags.rd = rd;  }
    bool qr()                   { return m_flags.qr;}
    void qdinc()                { ++m_qdcount;      }
    unsigned short qdcount()    { return m_qdcount; }
    unsigned short ancount()    { return m_ancount; }

private:
    unsigned short m_id;        // identifier
    unsigned short m_qdcount;   // num of questions
    unsigned short m_ancount;   // num of resources
    unsigned short m_nscount;   // num of authorative resources
    unsigned short m_arcount;   // num of additional resources

    struct {
        bool qr;                // query or responce
        unsigned char opcode;   // kind of quert
        bool aa;                // authorative answer
        bool tc;                // TrunCation
        bool rd;                // Recursion Desired
        bool ra;                // Recursion Available
        unsigned char z;        // --
        unsigned char rcode;    // Response code(error etc.)
    } m_flags;

    // Encode and decode flags
    void flag_dec(uint16_t flag); // decode from buffer
    uint16_t flag_enc();          // encode to buffer
};

class Name
{
//    1  1  1  1  1  1
//    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |                                               |
//    /                     QNAME                     /
//    /                                               /
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |                     QTYPE                     |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |                     QCLASS                    |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
public:
    Name();
    Name(const char* name);
    Name(std::string name);
    Name(const dns::Name* name);
    virtual ~Name(){};

    int toBuffer(unsigned char* buf, size_t size);
    bool fromBuffer(unsigned char* buf, size_t len, size_t& offset);

    std::string toString();

private:
    static const char *s_szValidChars;
    size_t m_length;
    std::list<std::string> m_parts;
    void parse(std::string& name); // parse and decode are the MAIN
    bool decode(unsigned char* buf, size_t size, size_t &offset,std::list<std::string>& results, size_t &len);
};

class Question
{
//    1  1  1  1  1  1
//    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |                                               |
//    /                                               /
//    /                      NAME                     /
//    |                                               |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |                      TYPE                     |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |                     CLASS                     |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |                      TTL                      |
//    |                                               |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |                   RDLENGTH                    |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
//    /                     RDATA                     /
//    /                                               /
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
public:
    Question(const std::string& qname, unsigned short qtype);
    Question(const dns::Name& qname, unsigned short qtype, unsigned short qclass);
    virtual ~Question(){};

    std::string toString();

    int toBuffer(unsigned char *buf, size_t size);
    static Question* fromBuffer(unsigned char* buf, size_t size, size_t& offset);

private:
    dns::Name m_name;       // an owner rr_name
    unsigned short m_type;  // RR TYPE
    unsigned short m_class; // RR CLASS
};

class ResourceRecord
{
//    1  1  1  1  1  1
//    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |                                               |
//    /                                               /
//    /                      NAME                     /
//    |                                               |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |                      TYPE                     |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |                     CLASS                     |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |                      TTL                      |
//    |                                               |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |                   RDLENGTH                    |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
//    /                     RDATA                     /
//    /                                               /
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

public:
    ResourceRecord(unsigned short rtype, unsigned short rdlen = 0);
    virtual ~ResourceRecord(){};
    bool    fromBuffer(unsigned char* buf, size_t size, size_t& offset);
    virtual std::string     toString(int debug = false);

protected:
    Name rr_name;                // a domain name
    unsigned short  rr_type;     // RR type codes
    unsigned short  rr_class;    // class of the data
    unsigned int    rr_ttl;      // time to live
    unsigned short  rr_rdlen;    // length in octets of the RDATA field
    unsigned int    ip_addr;       // RDATA, which is a ip address

    // Pack and unpack RDATA, get ip_addr
    bool dataFromBuffer(unsigned char* buf, size_t size, size_t& offset);
};

class Message
{
//    +---------------------+
//    |        msg_header       |
//    +---------------------+
//    |       Question      | the question for the rr_name server
//    +---------------------+
//    |        Answer       | RRs answering the question
//    +---------------------+
//    |      Authority      | RRs pointing toward an authority
//    +---------------------+
//    |      Additional     | RRs holding additional information
//    +---------------------+
public:
    Message(){};
    Message(const std::string& qname, unsigned short qtype){addQuestion(qname, qtype);};
    virtual ~Message(){};

    void    addQuestion(const std::string& qname, unsigned short qtype); // append questions
    int     toBuffer(unsigned char* buf, size_t size); // write into buffer
    bool    fromBuffer(unsigned char* buf, size_t size); // read from buffer


    inline dns::Header& header() {return msg_header; };
    std::string toString(); // convert to string
    std::string getOneAddress(); // return one from possible many address

protected:
    dns::Header msg_header;
    std::list<dns::Question*> questions;
    std::list<dns::ResourceRecord*> resources;
    void clearList();
};

class Resolver
{
public:
    Resolver(); // Use default DNS server
    Resolver(const char* host, unsigned short port = DEFAULT_DNS_PORT); // DNS server
    Resolver(const std::string& host, unsigned short port = DEFAULT_DNS_PORT); // DNS server
    virtual ~Resolver(){};

    bool resolve(const char* name, unsigned short type, Message& response);
    bool resolve(const std::string& name, unsigned short type, Message& response);
    //bool resolve(Message& query, Message& response);
    bool resolve(dns::Message& query, dns::Message& response, unsigned char *buf = 0, size_t *size = 0);

private:
    network::UdpSocket m_socket;
};

DNS_END

std::string getDomaimAddress(const char *domain);
std::string getDomaimAddress(const std::string& domain);
int         getResponce(const char *domain, unsigned char *buffer, size_t *size);

#endif //DNS_DNSSERVER_H
