#ifndef IPV4_FUSCATION_H
#define IPV4_FUSCATION_H

#include "Common.h"
#include <stdint.h>

bool generate_ipv4_output(const char* output_file);
bool generate_ipv4_text_output(const char* output_file);
bool generate_ipv4_json_output(const char* output_file);

#endif 
