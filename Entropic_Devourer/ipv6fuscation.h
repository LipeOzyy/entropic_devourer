#ifndef IPV6_FUSCATION_H
#define IPV6_FUSCATION_H

#include "Common.h"
#include <stdint.h>

bool generate_ipv6_output(const char* output_file);
bool generate_ipv6_text_output(const char* output_file);
bool generate_ipv6_json_output(const char* output_file);

#endif 
