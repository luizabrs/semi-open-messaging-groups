#pragma once

#include <cstdio>
#include <cstddef>
#include <string>

void printhex(unsigned char *buf, size_t buflen);
std::string hex_to_string(unsigned char *buf, size_t buflen);