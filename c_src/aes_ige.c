#ifdef __WIN32__
    #include <windows.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "erl_nif.h"

#define OPENSSL_THREAD_DEFINES
#include <openssl/opensslconf.h>

#include <openssl/crypto.h>
#include <openssl/aes.h>

#define MAX_BYTES_TO_NIF 20000
static ERL_NIF_TERM atom_true;
static ERL_NIF_TERM atom_false;

static ERL_NIF_TERM crypt(ErlNifEnv* env, int argc,
                                          const ERL_NIF_TERM argv[])
{/* (Key, IVec, Data, IsEncrypt) */
  ErlNifBinary key_bin, ivec_bin, data_bin;
  AES_KEY aes_key;
  unsigned char ivec[32];
  int i;
  unsigned char* ret_ptr;
  ERL_NIF_TERM ret;    

  if (!enif_inspect_iolist_as_binary(env, argv[0], &key_bin)
    || (key_bin.size != 16 && key_bin.size != 32)
    || !enif_inspect_binary(env, argv[1], &ivec_bin)
    || ivec_bin.size != 32
    || !enif_inspect_iolist_as_binary(env, argv[2], &data_bin)
    || data_bin.size % 16 != 0) {
    return enif_make_badarg(env);
  }

  if (argv[3] == atom_true) {
    i = AES_ENCRYPT;
    AES_set_encrypt_key(key_bin.data, key_bin.size*8, &aes_key);
  } else {
    i = AES_DECRYPT;
    AES_set_decrypt_key(key_bin.data, key_bin.size*8, &aes_key);
  }

  ret_ptr = enif_make_new_binary(env, data_bin.size, &ret);
  memcpy(ivec, ivec_bin.data, 32);
  AES_ige_encrypt(data_bin.data, ret_ptr, data_bin.size, &aes_key, ivec, i);

  int cost = (data_bin.size  * 100) / MAX_BYTES_TO_NIF;
  if (cost) enif_consume_timeslice(env, (cost > 100) ? 100 : cost);
 
  return ret;
}

static ERL_NIF_TERM bi_crypt(ErlNifEnv* env, int argc,
                                          const ERL_NIF_TERM argv[])
{/* (Key1, Key2, IVec, Data, IsEncrypt) */
  ErlNifBinary key1_bin, key2_bin, ivec_bin, data_bin;
  AES_KEY aes_key1, aes_key2;
  unsigned char ivec[64];
  int i;
  unsigned char* ret_ptr;
  ERL_NIF_TERM ret;    

  if (!enif_inspect_iolist_as_binary(env, argv[0], &key1_bin)
    || (key1_bin.size != 16 && key1_bin.size != 32)
    || !enif_inspect_iolist_as_binary(env, argv[1], &key2_bin)
    || (key2_bin.size != 16 && key2_bin.size != 32)
    || !enif_inspect_binary(env, argv[2], &ivec_bin)
    || ivec_bin.size != 64
    || !enif_inspect_iolist_as_binary(env, argv[3], &data_bin)
    || data_bin.size % 16 != 0) {
    return enif_make_badarg(env);
  }

  if (argv[4] == atom_true) {
    i = AES_ENCRYPT;
    AES_set_encrypt_key(key1_bin.data, key1_bin.size*8, &aes_key1);
    AES_set_encrypt_key(key2_bin.data, key2_bin.size*8, &aes_key2);
  } else {
    i = AES_DECRYPT;
    AES_set_decrypt_key(key1_bin.data, key1_bin.size*8, &aes_key1);
    AES_set_decrypt_key(key2_bin.data, key2_bin.size*8, &aes_key2);
  }

  ret_ptr = enif_make_new_binary(env, data_bin.size, &ret);
  memcpy(ivec, ivec_bin.data, 64);
  AES_bi_ige_encrypt(data_bin.data, ret_ptr, data_bin.size, &aes_key1, &aes_key2, ivec, i);

  int cost = (data_bin.size  * 100) / MAX_BYTES_TO_NIF;
  if (cost) enif_consume_timeslice(env, (cost > 100) ? 100 : cost);
 
  return ret;
}

static int on_load(ErlNifEnv* env, void** priv_data, ERL_NIF_TERM load_info)
{
  atom_true = enif_make_atom(env, "true");
  atom_false = enif_make_atom(env, "false");
  return 0;
}

static ErlNifFunc nif_funcs[] =
{
  {"crypt", 4, crypt},
  {"bi_crypt", 5, bi_crypt}
};

ERL_NIF_INIT(aes_ige, nif_funcs, &on_load, NULL, NULL, NULL);
