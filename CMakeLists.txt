cmake_minimum_required(VERSION 3.7)
project(dns)

set(CMAKE_CXX_STANDARD 11)

set(SOURCE_FILES
        main.cpp
        DnsServer.h
        Config.h
        Header.cpp
        Message.cpp
        Name.cpp
        Network.cpp
        Question.cpp
        Resolver.cpp
        ResourceRecord.cpp
        DnsServer.h)

add_executable(dns ${SOURCE_FILES})