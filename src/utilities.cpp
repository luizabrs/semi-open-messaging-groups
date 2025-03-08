#include "utilities.hpp"
#include <sstream>
#include <iomanip>

void printhex(unsigned char *buf, size_t buflen)
{
    for (int i = 0; i < buflen; i++)
    {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

std::string hex_to_string(unsigned char *buf, size_t buflen)
{
    std::stringstream ss;
    for(auto i = 0; i < buflen; ++i)
    {
        ss << std::hex << std::setfill('0') << std::setw(2) << (int) buf[i];
    }
    return ss.str();
}