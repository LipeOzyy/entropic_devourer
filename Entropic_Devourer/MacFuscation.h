#ifndef MAC_FUSCATION_H
#define MAC_FUSCATION_H

#include "Common.h"
#include <stdint.h>

bool generate_mac_output(const char* output_file);
bool generate_mac_text_output(const char* output_file);
bool generate_mac_json_output(const char* output_file);

#endif 
