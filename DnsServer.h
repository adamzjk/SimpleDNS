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
public:
    Header();
    virtual ~Header();

    int toBuffer(unsigned char* buf, size_t size);
    bool fromBuffer(unsigned char* buf, size_t size, size_t& offset);
    std::string toString();
    unsigned short idset(unsigned short id = 0);

    void rdset(bool rd)         { m_flags.rd = rd;  }
    bool qr()                   { return m_flags.qr;}
    void qdinc()                { ++m_qdcount;      }
    unsigned short qdcount()    { return m_qdcount; }
    unsigned short ancount()    { return m_ancount; }

private:
    unsigned short m_id;
    unsigned short m_qdcount;
    unsigned short m_ancount;
    unsigned short m_nscount;
    unsigned short m_arcount;

    struct {
        bool qr;
        unsigned char opcode;
        bool aa;
        bool tc;
        bool rd;
        bool ra;
        unsigned char z;
        unsigned char rcode;
    } m_flags;

    // Encode and decode flags
    void flag_dec(uint16_t flag);
    uint16_t flag_enc();
};

class Name
{
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
    void parse(std::string& name);
    bool decode(unsigned char* buf, size_t size, size_t &offset,std::list<std::string>& parts, size_t &len);
};

class Question
{
public:
    Question(const std::string& qname, unsigned short qtype);
    Question(const dns::Name& qname, unsigned short qtype, unsigned short qclass);
    virtual ~Question();

    std::string toString();

    int toBuffer(unsigned char *buf, size_t size);
    static Question* fromBuffer(unsigned char* buf, size_t size, size_t& offset);

private:
    dns::Name m_name;
    unsigned short m_type;
    unsigned short m_class;
};

class ResourceRecord
{
public:
    ResourceRecord(unsigned short rtype, unsigned short rdlen = 0);
    virtual ~ResourceRecord(){};
    bool    fromBuffer(unsigned char* buf, size_t size, size_t& offset);
    virtual std::string     toString(int debug = false);

protected:
    Name m_name;
    unsigned short  m_type;
    unsigned short  m_class;
    unsigned int    m_ttl;
    unsigned short  m_rdlen;
    unsigned int    m_ip;

    // Pack and unpack RDATA, redefined by derived class
    bool dataFromBuffer(unsigned char* buf, size_t size, size_t& offset);
};

class Message
{
public:
    Message(){};
    Message(const std::string& qname, unsigned short qtype){addQuestion(qname, qtype);};
    virtual ~Message(){};

    void    addQuestion(const std::string& qname, unsigned short qtype);
    int     toBuffer(unsigned char* buf, size_t size);
    bool    fromBuffer(unsigned char* buf, size_t size);


    inline dns::Header& header() {return m_header; };
    std::string toString();
    std::string getOneAddress();

protected:
    dns::Header m_header;
    std::list<dns::Question*> m_questions;
    std::list<dns::ResourceRecord*> m_answers;
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
