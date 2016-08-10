/*
 * Copyright (c) 2016 Cossack Labs Limited
 */


#include <themis/themis.h>
#include "base64.h"
#include <string.h>

#define MAX_KEY_LENGTH 10*1024

char* gen_key(){
  uint8_t private_key[MAX_KEY_LENGTH];
  uint8_t public_key[MAX_KEY_LENGTH];
  size_t private_key_length=MAX_KEY_LENGTH;
  size_t public_key_length=MAX_KEY_LENGTH;
  if(THEMIS_SUCCESS==themis_gen_ec_key_pair(private_key, &private_key_length, public_key, &public_key_length)){
    size_t base64_private_key_length, base64_public_key_length;
    char* base64_private_key=base64(private_key, private_key_length, &base64_private_key_length);
    char* base64_public_key=base64(public_key, public_key_length, &base64_public_key_length);
    char* res=malloc(base64_private_key_length+base64_public_key_length+2);
    sprintf(res, "%s %s", base64_private_key, base64_public_key);
    free(base64_private_key);
    free(base64_public_key);
    soter_rand(private_key, private_key_length);
    return res;
  }
  return NULL;
}


