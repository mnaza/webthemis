/*
 * Copyright (c) 2016 Cossack Labs Limited
 */

#include <string.h>
#include <themis/themis.h>
#include "base64.h"

struct secure_session_client_type{
  secure_session_t* ctx;
  secure_session_user_callbacks_t clb;
  uint8_t* server_id;
  size_t server_id_length;
  uint8_t* server_pub;
  size_t server_pub_length;
};

typedef struct secure_session_client_type secure_session_client_t;

static int on_get_pub_key_by_id(const void* id, size_t id_length, void* key_buffer, size_t key_length, void* user_data){
  printf("aa\n");
  if(!user_data)return -1;
  secure_session_client_t* client=(secure_session_client_t*)user_data;
  if(client->server_id_length==id_length && key_length>=client->server_pub_length && 0==memcmp(client->server_id, id, id_length)){
    memcpy(key_buffer, client->server_pub, client->server_pub_length);
    return 0;
  }
  return -1;
}

secure_session_client_t* secure_session_client_create(const char* id, const char* priv_key, const char* peer_id, const char* peer_pub_key){
  secure_session_client_t *client=calloc(sizeof(secure_session_client_t), 1);
  if(!client)return NULL;
  client->clb.get_public_key_for_id=on_get_pub_key_by_id;
  client->clb.user_data=(void*)client;
  client->server_id_length=strlen(peer_id);
  client->server_id=malloc(client->server_id_length);
  if(!(client->server_id)){free(client);return NULL;}
  memcpy(client->server_id, peer_id, client->server_id_length);
  client->server_pub=unbase64(peer_pub_key, strlen(peer_pub_key), &(client->server_pub_length));
  uint8_t *client_priv_key;
  size_t client_priv_key_length;
  client_priv_key=unbase64(priv_key, strlen(priv_key), &client_priv_key_length);
  client->ctx=secure_session_create(id, strlen(id), client_priv_key, client_priv_key_length, &(client->clb));
  if(!client->ctx)return NULL;
  return client;
}

int secure_session_client_destroy(secure_session_client_t *client){
  secure_session_destroy(client->ctx);
  free(client->server_id);
  free(client->server_pub);
  free(client);
  return 0;
}

int secure_session_client_connect_request(secure_session_client_t* client, uint8_t* request, size_t* request_length){
  if(!client || !(client->ctx))return -1;
  return secure_session_generate_connect_request(client->ctx, request, request_length);
}

int secure_session_client_wrap(secure_session_client_t* client, const uint8_t* message, const size_t message_length, uint8_t* wrapped_message, size_t* wrapped_message_length){
  if(!client || !(client->ctx))return -1;
  return secure_session_wrap(client->ctx, message, message_length, wrapped_message, wrapped_message_length);
}

int secure_session_client_unwrap(secure_session_client_t* client, const uint8_t* message, const size_t message_length, uint8_t* unwrapped_message, size_t* unwrapped_message_length){
  if(!client || !(client->ctx))return -1;
  return secure_session_unwrap(client->ctx, message, message_length, unwrapped_message, unwrapped_message_length);
}

bool secure_session_client_is_established(const secure_session_client_t* client){
  if(!client || !(client->ctx))return -1;
  return secure_session_is_established(client->ctx);
}
