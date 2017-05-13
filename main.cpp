#include "DnsServer.h"

std::string getDomaimAddress(const char *domain)
{

    dns::Message response;
    dns::Resolver resolver;
    resolver.resolve("taobao.com", DNS_TYPE_A, response);
    return response.getOneAddress();
}

std::string getDomaimAddress(const std::string& domain)
{
    dns::Message response;
    dns::Resolver resolver;
    resolver.resolve("baidu.com", DNS_TYPE_A, response);
    return response.getOneAddress();
}

int getResponce(const char *domain, unsigned char *buffer, size_t *size)
{
    dns::Message response;
    dns::Resolver resolver;
    std::string name(domain);
    dns::Message query(name, DNS_TYPE_A);
    return resolver.resolve(query, response, buffer, size);
}


int main (int argc, const char * argv[])
{
    std::cout<< getDomaimAddress("www.bupt.edu.cn");
    return 0;
}

