/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/* dbus-transport-kdbus.c  kdbus subclasses of DBusTransport
 *
 * Copyright (C) 2002, 2003, 2004, 2006  Red Hat Inc
 * Copyright (C) 2013  Samsung Electronics
 *
 * Licensed under the Academic Free License version 2.1
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */
#include "../config.h"
#include "dbus-transport.h"
#include "dbus-transport-kdbus.h"
#include "dbus-transport-protected.h"
#include "dbus-connection-internal.h"
#include <linux/kdbus.h>
#include "dbus-watch.h"
#include "dbus-errors.h"
#include "dbus-bus.h"
#include "kdbus-common.h"
#include <linux/types.h>
#include <fcntl.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <limits.h>
#include <sys/stat.h>

/**
 * @defgroup DBusTransportKdbus DBusTransport implementations for kdbus
 * @ingroup  DBusInternals
 * @brief Implementation details of DBusTransport on kdbus
 *
 * @{
 */

/** Default Size of the memory area for received non-memfd messages. */
#define RECEIVE_POOL_SIZE_DEFAULT_SIZE (2 * 1024LU * 1024LU)
/** Name of environmental variable to define receive pool size*/
#define RECEIVE_POOL_SIZE_ENV_VAR_NAME "KDBUS_MEMORY_POOL_SIZE"
/** Max size of pool size in megabytes*/
#define RECEIVE_POOL_SIZE_MAX_MBYTES 64
/** Min size of pool size in kilobytes*/
#define RECEIVE_POOL_SIZE_MIN_KBYTES 16

/** Over this memfd is used to send (if it is not broadcast). */
#define MEMFD_SIZE_THRESHOLD (512 * 1024LU)

/** Define max bytes read or written in one iteration.
* This is to avoid blocking on reading or writing for too long. It is checked after each message is sent or received,
* so if message is bigger than MAX_BYTES_PER_ITERATION it will be handled in one iteration, but sending/writing
* will break after that message.
**/
#define MAX_BYTES_PER_ITERATION 16384

#if (MEMFD_SIZE_THRESHOLD > KDBUS_MSG_MAX_PAYLOAD_VEC_SIZE)
  #error  Memfd size threshold higher than max kdbus message payload vector size
#endif

/** Enables verbosing more information about kdbus message.
 *  Works only if DBUS_VERBOSE=1 is used.
 */
#define KDBUS_MSG_DECODE_DEBUG 0

#define MSG_ITEM_BUILD_VEC(data, datasize)                                \
        item->type = KDBUS_ITEM_PAYLOAD_VEC;                              \
        item->size = KDBUS_ITEM_HEADER_SIZE + sizeof(struct kdbus_vec);   \
        item->vec.address = (unsigned long) data;                         \
        item->vec.size = datasize;

/**
 * Opaque object representing a transport.
 */
typedef struct DBusTransportKdbus DBusTransportKdbus;

/**
 * Implementation details of DBusTransportKdbus. All members are private.
 */
struct DBusTransportKdbus
{
  DBusTransport base;                   /**< Parent instance */
  int fd;                               /**< File descriptor. */
  DBusWatch *read_watch;                /**< Watch for readability. */
  DBusWatch *write_watch;               /**< Watch for writability. */

  int max_bytes_read_per_iteration;     /**< To avoid blocking too long. */
  int max_bytes_written_per_iteration;  /**< To avoid blocking too long. */

  void* kdbus_mmap_ptr;                 /**< Mapped memory where kdbus (kernel) writes
                                         *   messages incoming to us.
                                         */
  uint32_t receive_pool_size;           /**< Size of mapped memory buffer pointed by kdbus_mmap_ptr*/
  struct kdbus_bloom_parameter bloom;   /**< bloom parameters*/
  char* my_DBus_unique_name;               /**< unique name in DBus string format - :1.x , where x is kdbus id*/
  __u64 my_kdbus_id;                      /**< unique id given by kdbus bus*/
  char* activator;                      /**< well known name for activator */
  Matchmaker *matchmaker;            /**< for match rules management */
#if defined(POLICY_IN_LIB) && !defined(REMOVE_POLICY_FROM_DAEMON)
  PBusClientPolicy *policy;               /**< for checking policies in library */
#endif
  char *daemon_unique_name;                 /**< unique name of the dbus-daemon (org.freedesktop.DBus owner)*/
  dbus_uint32_t client_serial;           /**< serial number for messages synthesized by library*/
};

/**
 *  Gets size in bytes of bloom filter field.
 *  This size is got from the bus during connection procedure.
 *  @param transport transport
 *  @returns size of bloom
 */
__u64
dbus_transport_get_bloom_size(DBusTransport *transport)
{
  return ((DBusTransportKdbus*)transport)->bloom.size;
}

/**
 *  Gets hash count of bloom filter field.
 *
 *  @param transport transport
 *  @returns hash_n
 */
__u64
dbus_transport_get_bloom_n_hash(DBusTransport *transport)
{
  return ((DBusTransportKdbus*)transport)->bloom.n_hash;
}

/**
 *  Gets pointer to the memory pool, wher received messages are
 *  placed and some ioctls return their info
 *  @param transport transport
 *  @returns pointer to the pool
 */
void*
dbus_transport_get_pool_pointer(DBusTransport *transport)
{
  return ((DBusTransportKdbus*)transport)->kdbus_mmap_ptr;
}

#ifdef MATCH_IN_LIB
/**
 *  @param transport transport
 *  @returns matchmaker of the transport(connection)
 */
Matchmaker *
dbus_transport_get_matchmaker(DBusTransport* transport)
{
  return ((DBusTransportKdbus*)transport)->matchmaker;
}
#endif

#if defined(POLICY_IN_LIB) && !defined(REMOVE_POLICY_FROM_DAEMON)
/**
 *  @param transport transport
 *  @returns policy object
 */
PBusClientPolicy*
dbus_transport_get_policy(DBusTransport* transport)
{
  return ((DBusTransportKdbus*)transport)->policy;
}
#endif

/**
 * Puts locally generated message into received messages queue
 * @param message message that will be added
 * @param connection connection to which message will be added
 * @returns TRUE on success, FALSE on memory allocation error
 */
static dbus_bool_t
add_message_to_received(DBusMessage     *message,
                        DBusConnection  *connection)
{
  DBusList *message_link;

  message_link = _dbus_list_alloc_link (message);
  if (message_link == NULL)
    {
      dbus_message_unref (message);
      return FALSE;
    }

  _dbus_connection_queue_synthesized_message_link(connection, message_link);
  return TRUE;
}

static int
reply_with_error_preset_sender(char           *error_type,
                               const char     *template,
                               const char     *object,
                               DBusMessage    *message,
                               DBusConnection *connection,
                               const char     *sender)
{
  DBusMessage *errMessage;
  char* error_msg = "";

  if(template)
  {
    error_msg = alloca(strlen(template) + strlen(object) + 1);
    sprintf(error_msg, template, object);
  }
  else if(object)
    error_msg = (char*)object;

  errMessage = generate_local_error_message(dbus_message_get_serial(message), error_type, error_msg);

  if(errMessage == NULL)
     return -1;

  if (sender)
    dbus_message_set_sender(errMessage, sender);

  if (add_message_to_received(errMessage, connection))
    return 0;

  return -1;
}

/**
 * Generates local error message as a reply to message given as parameter
 * and adds generated error message to received messages queue.
 * @param error_type type of error, preferably DBUS_ERROR_(...)
 * @param template Template of error description. It can has formatting
 *      characters to print object string into it. Can be NULL.
 * @param object String to print into error description. Can be NULL.
 *      If object is not NULL while template is NULL, the object string
 *      will be the only error description.
 * @param message Message for which the error reply is generated.
 * @param connection The connection.
 * @returns 0 on success, otherwise -1
 */
static int
reply_with_error(char           *error_type,
                 const char     *template,
                 const char     *object,
                 DBusMessage    *message,
                 DBusConnection *connection)
{
  return reply_with_error_preset_sender(error_type, template,
      object, message, connection, NULL);
}

/**
 *  Generates reply to the message given as a parameter with one item in the reply body
 *  and adds generated reply message to received messages queue.
 *  @param message The message we are replying to.
 *  @param data_type Type of data sent in the reply.Use DBUS_TYPE_(...)
 *  @param pData Address of data sent in the reply.
 *  @param connection The connection
 *  @returns 0 on success, otherwise -1
 */
static int
reply_1_data(DBusMessage    *message,
             int             data_type,
             void           *pData,
             DBusConnection *connection)
{
  DBusMessageIter args;
  DBusMessage *reply;

  reply = dbus_message_new_method_return(message);
  if(reply == NULL)
    return -1;
  dbus_message_set_sender(reply, DBUS_SERVICE_DBUS);
  dbus_message_iter_init_append(reply, &args);
  if (!dbus_message_iter_append_basic(&args, data_type, pData))
    {
      dbus_message_unref(reply);
        return -1;
    }
  if(add_message_to_received(reply, connection))
    return 0;

  return -1;
}

static int
reply_ack(DBusMessage     *message,
          DBusConnection  *connection)
{
  DBusMessage *reply;

  reply = dbus_message_new_method_return(message);
  if(reply == NULL)
    return -1;
  if(add_message_to_received(reply, connection))
    return 0;
  return -1;
}

/**
 * Retrieves file descriptor to memory pool from kdbus module and stores
 * it in kdbus_transport->memfd. It is then used to send large message.
 * Triggered when message payload is over MEMFD_SIZE_THRESHOLD
 * @param kdbus_transport DBusTransportKdbus transport structure
 * @returns 0 on success, otherwise -1
 */
static int
kdbus_acquire_memfd(DBusTransportKdbus *kdbus_transport,
                    uint64_t            fsize)
{
  int er;
  struct kdbus_cmd_memfd_make mfd;

  mfd.size = sizeof(struct kdbus_cmd_memfd_make);
  mfd.file_size = fsize;

  if ((er = ioctl(kdbus_transport->fd, KDBUS_CMD_MEMFD_NEW, &mfd)) < 0)
    {
      _dbus_verbose("KDBUS_CMD_MEMFD_NEW failed (%d): %m\n", er);
      return -1;
    }

  _dbus_verbose("%s: memfd=%d\n", __FUNCTION__, mfd.fd);
  return mfd.fd;
}

/**
 * Allocates and initializes kdbus message structure.
 * @param name Well-known name or NULL. If NULL, dst_id must be supplied.
 * @param dst_id Numeric id of recipient. Ignored if name is not NULL.
 * @param body_size Size of message body (May be 0).
 * @param use_memfd Flag to build memfd message.
 * @param fds_count Number of file descriptors sent in the message.
 * @param transport transport
 * @returns initialized kdbus message or NULL if malloc failed
 */
static struct
kdbus_msg* kdbus_init_msg(const char         *name,
                          __u64               dst_id,
                          uint64_t            body_size,
                          dbus_bool_t         use_memfd,
                          int                 fds_count,
                          DBusTransportKdbus *transport)
{
  struct kdbus_msg* msg;
  uint64_t msg_size;

  msg_size = sizeof(struct kdbus_msg);

  if(use_memfd == TRUE)  // bulk data - memfd
      msg_size += KDBUS_ITEM_SIZE(sizeof(struct kdbus_memfd));
  else
    {
      msg_size += KDBUS_ITEM_SIZE(sizeof(struct kdbus_vec));  //header is a must
      while(body_size > KDBUS_MSG_MAX_PAYLOAD_VEC_SIZE)
        {
          msg_size += KDBUS_ITEM_SIZE(sizeof(struct kdbus_vec));
          body_size -= KDBUS_MSG_MAX_PAYLOAD_VEC_SIZE;
        }
      if((int64_t)body_size > 0)
        msg_size += KDBUS_ITEM_SIZE(sizeof(struct kdbus_vec));
    }

  if(fds_count)
    msg_size += KDBUS_ITEM_SIZE(sizeof(int)*fds_count);

  if (name)
    msg_size += KDBUS_ITEM_SIZE(strlen(name) + 1);
  else if (dst_id == KDBUS_DST_ID_BROADCAST)
    msg_size += KDBUS_ITEM_SIZE(sizeof(struct kdbus_bloom_filter) + transport->bloom.size);

  msg = malloc(msg_size);
  if (!msg)
  {
    _dbus_verbose("Error allocating memory for: %s,%s\n", _dbus_strerror (errno),
                  _dbus_error_from_errno (errno));
  return NULL;
  }

  memset(msg, 0, msg_size);
  msg->size = msg_size;
  msg->payload_type = KDBUS_PAYLOAD_DBUS;
  msg->dst_id = name ? 0 : dst_id;
  msg->src_id = transport->my_kdbus_id;

  return msg;
}

/*
 * Macros for SipHash algorithm
 */
#define ROTL(x,b) (uint64_t)( ((x) << (b)) | ( (x) >> (64 - (b))) )

#define U32TO8_LE(p, v)         \
    (p)[0] = (unsigned char)((v)      ); (p)[1] = (unsigned char)((v) >>  8); \
    (p)[2] = (unsigned char)((v) >> 16); (p)[3] = (unsigned char)((v) >> 24);

#define U64TO8_LE(p, v)         \
  U32TO8_LE((p),     (uint32_t)((v)      ));   \
  U32TO8_LE((p) + 4, (uint32_t)((v) >> 32));

#define U8TO64_LE(p) \
  (((uint64_t)((p)[0])      ) | \
   ((uint64_t)((p)[1]) <<  8) | \
   ((uint64_t)((p)[2]) << 16) | \
   ((uint64_t)((p)[3]) << 24) | \
   ((uint64_t)((p)[4]) << 32) | \
   ((uint64_t)((p)[5]) << 40) | \
   ((uint64_t)((p)[6]) << 48) | \
   ((uint64_t)((p)[7]) << 56))

#define SIPROUND            \
  do {              \
    v0 += v1; v1=ROTL(v1,13); v1 ^= v0; v0=ROTL(v0,32); \
    v2 += v3; v3=ROTL(v3,16); v3 ^= v2;     \
    v0 += v3; v3=ROTL(v3,21); v3 ^= v0;     \
    v2 += v1; v1=ROTL(v1,17); v1 ^= v2; v2=ROTL(v2,32); \
  } while(0)


/*
 * Hash keys for bloom filters
 */
const unsigned char hash_keys[8][16] =
{
  {0xb9,0x66,0x0b,0xf0,0x46,0x70,0x47,0xc1,0x88,0x75,0xc4,0x9c,0x54,0xb9,0xbd,0x15},
  {0xaa,0xa1,0x54,0xa2,0xe0,0x71,0x4b,0x39,0xbf,0xe1,0xdd,0x2e,0x9f,0xc5,0x4a,0x3b},
  {0x63,0xfd,0xae,0xbe,0xcd,0x82,0x48,0x12,0xa1,0x6e,0x41,0x26,0xcb,0xfa,0xa0,0xc8},
  {0x23,0xbe,0x45,0x29,0x32,0xd2,0x46,0x2d,0x82,0x03,0x52,0x28,0xfe,0x37,0x17,0xf5},
  {0x56,0x3b,0xbf,0xee,0x5a,0x4f,0x43,0x39,0xaf,0xaa,0x94,0x08,0xdf,0xf0,0xfc,0x10},
  {0x31,0x80,0xc8,0x73,0xc7,0xea,0x46,0xd3,0xaa,0x25,0x75,0x0f,0x9e,0x4c,0x09,0x29},
  {0x7d,0xf7,0x18,0x4b,0x7b,0xa4,0x44,0xd5,0x85,0x3c,0x06,0xe0,0x65,0x53,0x96,0x6d},
  {0xf2,0x77,0xe9,0x6f,0x93,0xb5,0x4e,0x71,0x9a,0x0c,0x34,0x88,0x39,0x25,0xbf,0x35}
};

/*
 * SipHash algorithm
 */
static void
_g_siphash24 (unsigned char       out[8],
              const void         *_in,
              size_t              inlen,
              const unsigned char k[16])
{
  uint64_t v0 = 0x736f6d6570736575ULL;
  uint64_t v1 = 0x646f72616e646f6dULL;
  uint64_t v2 = 0x6c7967656e657261ULL;
  uint64_t v3 = 0x7465646279746573ULL;
  uint64_t b;
  uint64_t k0 = U8TO64_LE (k);
  uint64_t k1 = U8TO64_LE (k + 8);
  uint64_t m;
  const unsigned char *in = _in;
  const unsigned char *end = in + inlen - (inlen % sizeof(uint64_t));
  const int left = inlen & 7;
  b = ((uint64_t) inlen) << 56;
  v3 ^= k1;
  v2 ^= k0;
  v1 ^= k1;
  v0 ^= k0;

  for (; in != end; in += 8)
    {
      m = U8TO64_LE (in);
      v3 ^= m;
      SIPROUND;
      SIPROUND;
      v0 ^= m;
    }

  switch (left)
    {
      case 7: b |= ((uint64_t) in[6]) << 48;
      case 6: b |= ((uint64_t) in[5]) << 40;
      case 5: b |= ((uint64_t) in[4]) << 32;
      case 4: b |= ((uint64_t) in[3]) << 24;
      case 3: b |= ((uint64_t) in[2]) << 16;
      case 2: b |= ((uint64_t) in[1]) <<  8;
      case 1: b |= ((uint64_t) in[0]); break;
      case 0: break;
    }

  v3 ^= b;
  SIPROUND;
  SIPROUND;
  v0 ^= b;

  v2 ^= 0xff;
  SIPROUND;
  SIPROUND;
  SIPROUND;
  SIPROUND;
  b = v0 ^ v1 ^ v2  ^ v3;
  U64TO8_LE (out, b);
}

static void
bloom_add_data (uint64_t                      bloom_data [],
                struct kdbus_bloom_parameter *bloom_params,
                const void                   *data,
                size_t                        n)
{
  unsigned char hash[8];
  uint64_t bit_num;
  unsigned int bytes_num = 0;
  unsigned int cnt_1, cnt_2;
  unsigned int hash_index = 0;

  unsigned int c = 0;
  uint64_t p = 0;

  bit_num = bloom_params->size * 8;

  if (bit_num > 1)
    bytes_num = ((__builtin_clzll(bit_num) ^ 63U) + 7) / 8;

  for (cnt_1 = 0; cnt_1 < bloom_params->n_hash; cnt_1++)
    {
      for (cnt_2 = 0, hash_index = 0; cnt_2 < bytes_num; cnt_2++)
        {
          if (c <= 0)
            {
              _g_siphash24(hash, data, n, hash_keys[hash_index++]);
              c += 8;
            }

          p = (p << 8ULL) | (uint64_t) hash[8 - c];
          c--;
        }

      p &= bit_num - 1;
      bloom_data[p >> 6] |= 1ULL << (p & 63);
    }
}

static void
bloom_add_pair (uint64_t                      bloom_data [],
                struct kdbus_bloom_parameter *bloom_params,
                const char                   *parameter,
                const char                   *value)
{
  char buf[1024];
  size_t size;

  size = strlen(parameter) + strlen(value) + 1;
  if (size > 1024)
    return;

  strcpy(stpcpy(stpcpy(buf, parameter), ":"), value);
  bloom_add_data (bloom_data, bloom_params, buf, size);
}

static void
bloom_add_prefixes (uint64_t                      bloom_data [],
              struct kdbus_bloom_parameter *bloom_params,
              const char                   *parameter,
              const char                   *value,
              char                          separator)
{
  char buf[1024];
  size_t size;

  size = strlen(parameter) + strlen(value) + 1;
  if (size > 1024)
    return;

  strcpy(stpcpy(stpcpy(buf, parameter), ":"), value);

  for (;;)
    {
      char *last_sep;
      last_sep = strrchr(buf, separator);
      if (!last_sep || last_sep == buf)
        break;

      *last_sep = 0;
      bloom_add_data (bloom_data, bloom_params, buf, last_sep-buf);
    }
}

static int
bus_message_setup_bloom(DBusMessage                  *msg,
                        struct kdbus_bloom_filter    *bloom,
                        struct kdbus_bloom_parameter *bloom_params)
{
  void *data;
  unsigned i;
  //int ret;
  const char *str;
  DBusMessageIter args;

  _dbus_assert(msg);
  _dbus_assert(bloom);

  data = bloom->data;
  memset(data, 0, bloom_params->size);
  bloom->generation = 0;

  bloom_add_pair(data, bloom_params, "message-type",
      dbus_message_type_to_string(dbus_message_get_type(msg))); //Fixme in systemd type invalid returns NULL but in dbus it returns "invalid"

  str = dbus_message_get_interface(msg);
  if (str)
    bloom_add_pair(data, bloom_params, "interface", str);
  str = dbus_message_get_member(msg);
  if (str)
    bloom_add_pair(data, bloom_params, "member", str);
  str = dbus_message_get_path(msg);
  if (str)
    {
      bloom_add_pair(data, bloom_params, "path", str);
      bloom_add_pair(data, bloom_params, "path-slash-prefix", str);
      bloom_add_prefixes(data, bloom_params, "path-slash-prefix", str, '/');
    }

  if(!dbus_message_iter_init(msg, &args))
    return 0;

  for (i = 0; i < 64; i++)
    {
      char type;
      char buf[sizeof("arg")-1 + 2 + sizeof("-slash-prefix")];
      char *e;

      type = dbus_message_iter_get_arg_type(&args);
      if (type != DBUS_TYPE_STRING &&
          type != DBUS_TYPE_OBJECT_PATH &&
          type != DBUS_TYPE_SIGNATURE)
        break;

      dbus_message_iter_get_basic(&args, &str);

      e = stpcpy(buf, "arg");
      if (i < 10)
              *(e++) = '0' + (char) i;
      else {
              *(e++) = '0' + (char) (i / 10);
              *(e++) = '0' + (char) (i % 10);
      }

      *e = 0;
      bloom_add_pair(data, bloom_params, buf, str);

      strcpy(e, "-dot-prefix");
      bloom_add_prefixes(data, bloom_params, buf, str, '.');
      strcpy(e, "-slash-prefix");
      bloom_add_prefixes(data, bloom_params, buf, str, '/');

      if(!dbus_message_iter_next(&args))
        break;
  }

  return 0;
}

#if defined(POLICY_IN_LIB) && !defined(REMOVE_POLICY_FROM_DAEMON)

static inline const char *
nonnull (const char *maybe_null,
         const char *if_null)
{
  return (maybe_null ? maybe_null : if_null);
}

/*Based on complain_about_message(), but with some differences*/
char *
prepare_error_msg_text (const char     *complaint,
                        int             matched_rules,
                        DBusMessage    *message,
                        const char  *sender_name,
                        dbus_bool_t     requested_reply)
{
  char *err_msg_text;
  const char *sender_loginfo;
  const char *proposed_recipient_loginfo;

  //TODO can pregenerate for local or ask kdbus for remote data
  sender_loginfo = "(unset)";

  //TODO can pregenerate for local or ask kdbus for remote data
  proposed_recipient_loginfo = "(unset)";


  if (asprintf(&err_msg_text,
      "%s, %d matched rules; type=\"%s\", sender=\"%s\" (%s) "
      "interface=\"%s\" member=\"%s\" error name=\"%s\" "
      "requested_reply=\"%d\" destination=\"%s\" (%s)",
      complaint,
      matched_rules,
      dbus_message_type_to_string (dbus_message_get_type (message)),
      sender_name,
      sender_loginfo,
      nonnull (dbus_message_get_interface (message), "(unset)"),
      nonnull (dbus_message_get_member (message), "(unset)"),
      nonnull (dbus_message_get_error_name (message), "(unset)"),
      requested_reply,
      nonnull (dbus_message_get_destination (message), DBUS_SERVICE_DBUS),
      proposed_recipient_loginfo) == -1)
    {
      return NULL;
    }
  else
    {
      return err_msg_text;
    }
}

static int
policy_get_libdbuspolicy_msg_type(DBusMessage* message)
{
  int libdbuspolicy_msg_type = 0;
  int dbus_msg_type = 0;

  dbus_msg_type = dbus_message_get_type(message);

  if (DBUS_MESSAGE_TYPE_METHOD_CALL == dbus_msg_type)
    libdbuspolicy_msg_type = 1;
    else if (DBUS_MESSAGE_TYPE_METHOD_RETURN == dbus_msg_type)
      libdbuspolicy_msg_type = 2;
    else if (DBUS_MESSAGE_TYPE_ERROR == dbus_msg_type)
      libdbuspolicy_msg_type = 4;
    else if (DBUS_MESSAGE_TYPE_SIGNAL == dbus_msg_type)
      libdbuspolicy_msg_type = 3;
    else
      _dbus_verbose("Messages should have type!\n");

  return libdbuspolicy_msg_type;
}

static int
policy_get_libdbuspolicy_msg_req_reply(DBusMessage* message)
{
  if (dbus_message_get_reply_serial(message) == 0)
      return NO_REQUESTED_REPLY;
  return REQUESTED_REPLY;
}

static dbus_bool_t
policy_check_can_send(PBusClientPolicy *policy, DBusMessage* message)
{
  if (dbus_policy_check_can_send(policy,
                                policy_get_libdbuspolicy_msg_type(message), /* message type */
                                dbus_message_get_destination(message), /* destination */
                                dbus_message_get_path(message), /* path */
                                dbus_message_get_interface(message), /* interface */
                                dbus_message_get_member(message), /* member */
                                dbus_message_get_error_name(message), /* error name */
                                dbus_message_get_reply_serial(message), /* reply serial */
                                policy_get_libdbuspolicy_msg_req_reply(message))) /* requested reply */
    {
      _dbus_verbose("Policy send check. This message is ok\n");
      return TRUE;
    }
  else
    {
      _dbus_verbose("Policy send check. I can't send this msg.\n");
      return FALSE;
    }
}

static dbus_bool_t
send_local_cant_send_error(DBusTransportKdbus* transport, DBusMessage* message)
{
  /* send error to ourselves */
  if (!(dbus_message_get_error_name(message) &&
      strcmp(dbus_message_get_error_name(message), DBUS_ERROR_ACCESS_DENIED) == 0))
    /*don't generate local error if msg is local error from checking policy for receiving
     * (for now it is only case of generating DBUS_ERROR_ACCESS_DENIED)*/
    {
      char *err_msg_text;
      dbus_bool_t requested_reply = FALSE;
      int ret = FALSE;
      if (dbus_message_get_reply_serial (message) != 0)
              requested_reply = TRUE;

      err_msg_text = prepare_error_msg_text("Rejected send message",
          -1 /*TODO insert real value from libdbuspolicy (patch is need)*/,
          message, transport->my_DBus_unique_name, requested_reply);
      if (!err_msg_text)
        return FALSE;

      ret = reply_with_error_preset_sender(DBUS_ERROR_ACCESS_DENIED, NULL,
              err_msg_text, message, transport->base.connection, DBUS_SERVICE_DBUS);
      free (err_msg_text);
      if (ret == -1)
        return FALSE;
    }
  return TRUE;
}

dbus_bool_t
policy_check_can_recv(PBusClientPolicy *policy, DBusMessage *message)
{
  if (dbus_policy_check_can_recv(policy,
                                policy_get_libdbuspolicy_msg_type(message), /* message type */
                                dbus_message_get_sender(message), /* sender! */
                                dbus_message_get_path(message), /* path */
                                dbus_message_get_interface(message), /* interface */
                                dbus_message_get_member(message), /* member */
                                dbus_message_get_error_name(message), /* error name */
                                dbus_message_get_reply_serial(message), /* reply serial */
                                policy_get_libdbuspolicy_msg_req_reply(message))) /* requested reply */
    {
      _dbus_verbose("Policy recv check. This message is ok\n");
      return TRUE;
    }
  else
    {
      _dbus_verbose("Policy recv check. I should drop this message\n");
      return FALSE;
    }
}

dbus_bool_t
send_cant_recv_error(DBusTransport* transport, DBusMessage *message)
{
  DBusMessage *errMessage = NULL;
  char *err_msg_text;
  dbus_bool_t ret = FALSE;
  dbus_bool_t requested_reply = FALSE;

  if (dbus_message_get_reply_serial(message) != 0)
    requested_reply = TRUE;

  err_msg_text = prepare_error_msg_text("Rejected receive message",
      -1 /*TODO insert real value from libdbuspolicy (patch is need)*/,
      message, dbus_message_get_sender(message), requested_reply);
  if (!err_msg_text)
    goto out;

  /* create and send error to origin of the message */
  errMessage = dbus_message_new_error(message,
                DBUS_ERROR_ACCESS_DENIED, err_msg_text);
  if (!errMessage)
    goto out;

  if (dbus_message_set_sender(errMessage, ":1.1") == FALSE) // error should look as from daemon
    goto out;

  if (_dbus_connection_send_unlocked_no_update_no_static(transport->connection,
            errMessage, NULL) == FALSE)
    goto out;

  ret = TRUE;

  out:
  if (err_msg_text)
    free(err_msg_text);
  if (errMessage)
    dbus_message_unref(errMessage);
  return ret;
}
#endif

/**
 * Sends DBus message using kdbus.
 * Handles broadcasts and unicast messages, and passing of Unix fds.
 * Also can locally generate error replies on some error returned by kernel.
 *
 * TODO refactor to be more compact - maybe we can send header always as a payload vector
 *  and only message body as memfd if needed.
 *
 * @param transport Transport.
 * @param message DBus message to be sent
 * @param destination Destination of the message.
 * @returns bytes sent or -1 if sending failed
 */
static int
kdbus_write_msg(DBusTransportKdbus  *transport,
                DBusMessage         *message,
                const char          *destination)
{
  struct kdbus_msg *msg = NULL;
  struct kdbus_item *item;
  uint64_t dst_id = KDBUS_DST_ID_BROADCAST;
  const DBusString *header;
  const DBusString *body;
  uint64_t ret_size = 0;
  uint64_t body_size = 0;
  uint64_t header_size = 0;
  int memfd = -1;
  const int *unix_fds;
  unsigned fds_count;
  dbus_bool_t autostart;

  // determine destination and destination id
  if(destination)
    {
      dst_id = KDBUS_DST_ID_NAME;
      if((destination[0] == ':') && (destination[1] == '1') && (destination[2] == '.'))  /* if name starts with ":1." it is a unique name and should be send as number */
        {
          errno = 0;
          dst_id = strtoull(&destination[3], NULL, 10);
          if(errno)
          {
            _dbus_verbose("error: unique name is not a number: %s (%m)\n", destination);
            ret_size = -1;
            goto out;
          }
          destination = NULL;
        }
    }

  _dbus_message_get_network_data (message, &header, &body);
  header_size = _dbus_string_get_length(header);
  body_size = _dbus_string_get_length(body);
  ret_size = header_size + body_size;

#if defined(POLICY_IN_LIB) && !defined(REMOVE_POLICY_FROM_DAEMON)
  /* TODO We could check policy earlier to safe some CPU cycles. */
  if(!policy_check_can_send(transport->policy, message))
    {
      if (send_local_cant_send_error(transport, message) == FALSE)
        ret_size = -1;
      goto out;
    }
#endif

  // check whether we can and should use memfd
  if((dst_id != KDBUS_DST_ID_BROADCAST) && (ret_size > MEMFD_SIZE_THRESHOLD))
      memfd = kdbus_acquire_memfd(transport, ret_size);

  _dbus_message_get_unix_fds(message, &unix_fds, &fds_count);

  // init basic message fields
  msg = kdbus_init_msg(destination, dst_id, body_size, memfd >= 0, fds_count, transport);
  if(msg == NULL)
    {
      _dbus_verbose("Can't allocate memory for new message\n");
      ret_size = -1;
      goto out;
    }
  msg->cookie = dbus_message_get_serial(message);
  autostart = dbus_message_get_auto_start (message);
  if(!autostart)
    msg->flags |= KDBUS_MSG_FLAGS_NO_AUTO_START;
  if((dbus_message_get_no_reply(message) == FALSE) && (dst_id != KDBUS_DST_ID_BROADCAST))
    {
      msg->flags |= KDBUS_MSG_FLAGS_EXPECT_REPLY;
      msg->timeout_ns = 50000000000ULL;
    }
  else
    msg->cookie_reply = dbus_message_get_reply_serial(message);

  // build message contents
  item = msg->items;

  if(memfd >= 0)
    {
      const char *data[2] = { _dbus_string_get_const_data(header), _dbus_string_get_const_data(body) };
      uint64_t count[2] = { header_size, body_size };
      int64_t wr;
      int p;

      _dbus_verbose("sending data via memfd\n");
      for (p = 0; p < 2; ++p)
        {
          while (count[p])
            {
              wr = write(memfd, data[p], count[p]);
              if (wr < 0)
                {
                  _dbus_verbose("writing to memfd failed: (%d) %m\n", errno);
                  ret_size = -1;
                  goto out;
                }
              count[p] -= wr;
              data[p] += wr;
            }
        }

      // seal data - kdbus module needs it
      if(ioctl(memfd, KDBUS_CMD_MEMFD_SEAL_SET, 1) < 0)
        {
          _dbus_verbose("memfd sealing failed: %d (%m)\n", errno);
          ret_size = -1;
          goto out;
        }

      item->type = KDBUS_ITEM_PAYLOAD_MEMFD;
      item->size = KDBUS_ITEM_HEADER_SIZE + sizeof(struct kdbus_memfd);
      item->memfd.size = ret_size;
      item->memfd.fd = memfd;
    }
  else
    {
      _dbus_verbose("sending data by vec\n");
      MSG_ITEM_BUILD_VEC(_dbus_string_get_const_data(header), header_size);

      if(body_size)
        {
          const char* body_data;

          body_data = _dbus_string_get_const_data(body);
          while(body_size > KDBUS_MSG_MAX_PAYLOAD_VEC_SIZE)
            {
              _dbus_verbose("attaching body part\n");
              item = KDBUS_ITEM_NEXT(item);
              MSG_ITEM_BUILD_VEC(body_data, KDBUS_MSG_MAX_PAYLOAD_VEC_SIZE);
              body_data += KDBUS_MSG_MAX_PAYLOAD_VEC_SIZE;
              body_size -= KDBUS_MSG_MAX_PAYLOAD_VEC_SIZE;
            }
          if(body_size)
            {
              _dbus_verbose("attaching body part\n");
              item = KDBUS_ITEM_NEXT(item);
              MSG_ITEM_BUILD_VEC(body_data, body_size);
            }
        }
    }

  if(fds_count)
    {
      item = KDBUS_ITEM_NEXT(item);
      item->type = KDBUS_ITEM_FDS;
      item->size = KDBUS_ITEM_HEADER_SIZE + (sizeof(int) * fds_count);
      memcpy(item->fds, unix_fds, sizeof(int) * fds_count);
    }

  if (destination)
    {
      item = KDBUS_ITEM_NEXT(item);
      item->type = KDBUS_ITEM_DST_NAME;
      item->size = KDBUS_ITEM_HEADER_SIZE + strlen(destination) + 1;
      memcpy(item->str, destination, item->size - KDBUS_ITEM_HEADER_SIZE);
    }
  else if (dst_id == KDBUS_DST_ID_BROADCAST)
    {
      item = KDBUS_ITEM_NEXT(item);
      item->type = KDBUS_ITEM_BLOOM_FILTER;
      item->size = KDBUS_ITEM_SIZE(sizeof(struct kdbus_bloom_filter) + transport->bloom.size);
      bus_message_setup_bloom(message, &item->bloom_filter, &transport->bloom);
    }

  again:
  if (ioctl(transport->fd, KDBUS_CMD_MSG_SEND, msg))
    {
      _dbus_verbose("kdbus error sending message: err %d (%m)\n", errno);
      if(errno == EINTR)
        goto again;
      else if(errno == ENXIO) //no such id on the bus
        {
          if(!reply_with_error(DBUS_ERROR_NAME_HAS_NO_OWNER, "Name \"%s\" does not exist", dbus_message_get_destination(message), message, transport->base.connection))
              goto out;
        }
      else if((errno == ESRCH) || (errno == EADDRNOTAVAIL) || (errno == ECONNRESET))  //when well known name is not available on the bus
        {
          if(autostart)
            {
              if(!reply_with_error(DBUS_ERROR_SERVICE_UNKNOWN, "The name %s was not provided by any .service files", dbus_message_get_destination(message), message, transport->base.connection))
                  goto out;
            }
          else
            if(!reply_with_error(DBUS_ERROR_NAME_HAS_NO_OWNER, "Name \"%s\" does not exist", dbus_message_get_destination(message), message, transport->base.connection))
                goto out;
        }
      else if (errno == EMLINK)
        {
          if(!reply_with_error(DBUS_ERROR_LIMITS_EXCEEDED, NULL, "The maximum number of pending replies per connection has been reached", message, transport->base.connection))
              goto out;
        }
      else if (errno == ENOBUFS || errno == EXFULL)
        {
          if(!reply_with_error(DBUS_ERROR_LIMITS_EXCEEDED, NULL, "No space in receiver's buffer", message, transport->base.connection))
              goto out;
        }
      ret_size = -1;
    }
  out:
  if(msg)
    free(msg);
  if(memfd >= 0)
    close(memfd);

  return ret_size;
}

/**
 * Performs kdbus hello - registration on the kdbus bus
 * needed to send and receive messages on the bus,
 * and configures transport.
 * As a result unique id on he bus is obtained.
 *
 * @see KDBUS_HELLO_* flags in kdbus.h
 *
 * @param transport transport structure
 * @param registration_flags aditional flags to modify registration process
 * @returns #TRUE on success
 */
static dbus_bool_t
bus_register_kdbus(DBusTransportKdbus *transport,
                   dbus_uint32_t       registration_flags,
                   DBusError          *error)
{
  struct kdbus_cmd_hello  *hello;
  struct kdbus_item       *item;
  __u64 hello_size;
  __u64 item_size = 0;
  __u64 receive_pool_size = RECEIVE_POOL_SIZE_DEFAULT_SIZE;
  const char *env_pool;

  hello_size = sizeof(struct kdbus_cmd_hello);
  if(transport->activator != NULL)
    {
      item_size = KDBUS_ITEM_HEADER_SIZE + strlen(transport->activator) + 1;
      hello_size += item_size;
    }

  hello = alloca(hello_size);
  memset(hello, 0, hello_size);

  hello->conn_flags = KDBUS_HELLO_ACCEPT_FD;
  hello->attach_flags = 0;

  env_pool = _dbus_getenv (RECEIVE_POOL_SIZE_ENV_VAR_NAME);
  if(env_pool)
    {
      __u64 size;
      unsigned int multiply = 1;
      long int page_size;

      page_size = sysconf(_SC_PAGESIZE);
      if(page_size == -1)
        {
          size = 0;
          goto finish;
        }

      errno = 0;
      size = strtoul(env_pool, (char**)&env_pool, 10);
      if((errno == EINVAL) || size == 0)
        {
          size = 0;
          goto finish;
        }

      if(*env_pool == 'k')
        {
          multiply = 1024;
          env_pool++;
        }
      else if (*env_pool == 'M')
        {
          multiply = 1024 * 1024;
          env_pool++;
        }

      if(*env_pool != '\0')
        {
          size = 0;
          goto finish;
        }

      receive_pool_size = size * multiply;

      if((receive_pool_size > RECEIVE_POOL_SIZE_MAX_MBYTES * 1024 * 1024) ||
         (receive_pool_size < RECEIVE_POOL_SIZE_MIN_KBYTES * 1024) ||
         ((receive_pool_size & (page_size - 1)) != 0))  //pool size must be aligned to page size
        size = 0;

    finish:
      if(size == 0)
        {
          _dbus_warn("%s value is invalid, default value %luB will be used.\n", RECEIVE_POOL_SIZE_ENV_VAR_NAME,
                      RECEIVE_POOL_SIZE_DEFAULT_SIZE);
          _dbus_warn("Correct value must be between %ukB and %uMB and must be aligned to page size: %ldB.\n",
                      RECEIVE_POOL_SIZE_MIN_KBYTES, RECEIVE_POOL_SIZE_MAX_MBYTES, page_size);

          receive_pool_size = RECEIVE_POOL_SIZE_DEFAULT_SIZE;
        }
    }

  _dbus_verbose ("Receive pool size set to %llu.\n", receive_pool_size);
  transport->receive_pool_size = receive_pool_size;
  hello->pool_size = receive_pool_size;

  if(transport->activator != NULL)
    {
       item = hello->items;
       memcpy(item->str, transport->activator, strlen(transport->activator) + 1);
       item->size = item_size;
       item->type = KDBUS_ITEM_NAME;
       hello->conn_flags |= KDBUS_HELLO_ACTIVATOR;
    }

  if (registration_flags & REGISTER_FLAG_MONITOR)
      hello->conn_flags |= KDBUS_HELLO_MONITOR;

  hello->size = hello_size;

  if (ioctl(transport->fd, KDBUS_CMD_HELLO, hello))
    {
      _dbus_verbose ("Failed to send hello (%d): %m\n",errno);
      dbus_set_error(error, DBUS_ERROR_FAILED, "Hello failed: %d, %m", errno);
      return FALSE;
    }

  transport->my_kdbus_id = hello->id;

  if(asprintf(&transport->my_DBus_unique_name, ":1.%020llu", (unsigned long long)hello->id) < 0)
    {
      dbus_set_error(error, DBUS_ERROR_NO_MEMORY, "Hello post failed: %d, %m", errno);
      return FALSE;
    }


  transport->kdbus_mmap_ptr = mmap(NULL, receive_pool_size, PROT_READ, MAP_SHARED, transport->fd, 0);
  if (transport->kdbus_mmap_ptr == MAP_FAILED)
    {
      _dbus_verbose("Error when mmap: %m, %d",errno);
      dbus_set_error(error, DBUS_ERROR_FAILED, "Hello mmap failed: %d, %m", errno);
      free(transport->my_DBus_unique_name);
      return FALSE;
    }

  _dbus_verbose("-- Our peer ID is: %llu\n", hello->id);
  transport->bloom = hello->bloom;

  return TRUE;
}

static dbus_bool_t
request_DBus_name (DBusTransport *transport,
                   DBusMessage   *msg,
                   int           *result,
                   DBusError     *error)
{
  DBusString service_name_real;
  const DBusString *service_name = &service_name_real;
  char* name;
  dbus_uint32_t flags;

  if (!dbus_message_get_args (msg, error,
                             DBUS_TYPE_STRING, &name,
                             DBUS_TYPE_UINT32, &flags,
                             DBUS_TYPE_INVALID))
   return FALSE;

  _dbus_string_init_const (&service_name_real, name);

  if (!_dbus_validate_bus_name (service_name, 0,
                               _dbus_string_get_length (service_name)))
   {
     dbus_set_error (error, DBUS_ERROR_INVALID_ARGS,
                     "Requested bus name \"%s\" is not valid", name);

     _dbus_verbose ("Attempt to acquire invalid service name\n");

     return FALSE;
   }

  if (_dbus_string_get_byte (service_name, 0) == ':')
   {
     /* Not allowed; only base services can start with ':' */
     dbus_set_error (error, DBUS_ERROR_INVALID_ARGS,
                     "Cannot acquire a service starting with ':' such as \"%s\"", name);

     _dbus_verbose ("Attempt to acquire invalid base service name \"%s\"", name);

     return FALSE;
   }

  if (_dbus_string_equal_c_str (service_name, DBUS_SERVICE_DBUS))
   {
     dbus_set_error (error, DBUS_ERROR_INVALID_ARGS,
                     "Connection is not allowed to own the service \"%s\"because "
                     "it is reserved for D-Bus' use only", DBUS_SERVICE_DBUS);
     return FALSE;
   }

#if defined(POLICY_IN_LIB) && !defined(REMOVE_POLICY_FROM_DAEMON)
  if (!dbus_policy_check_can_own(((DBusTransportKdbus*)transport)->policy, name))
    {
      dbus_set_error (error, DBUS_ERROR_ACCESS_DENIED,
              "Connection \"%s\" is not allowed to own the service \"%s\" due "
              "to security policies in the configuration file",
              ((DBusTransportKdbus*)transport)->my_DBus_unique_name, name);
      _dbus_verbose("Policy 'own' checked - I can't own name %s!\n", name);
      return FALSE;
    }
#endif

  *result = request_kdbus_name(transport, name, flags);
  if(*result == -EPERM)
   {
     dbus_set_error (error, DBUS_ERROR_ACCESS_DENIED,
         "Kdbus don't allow %s to own the service \"%s\"",
         ((DBusTransportKdbus*)transport)->my_DBus_unique_name, _dbus_string_get_const_data (service_name));
     return FALSE;
   }
  else if(*result < 0)
   {
     dbus_set_error (error, DBUS_ERROR_FAILED , "Name \"%s\" could not be acquired, %d, %m", name, errno);
     return FALSE;
   }

  return TRUE;
}

static dbus_bool_t
release_DBus_name (DBusTransport *transport,
                   DBusMessage   *msg,
                   int           *result,
                   DBusError     *error)
{
  const char *name;
  DBusString service_name;

  if (!dbus_message_get_args (msg, error,
                              DBUS_TYPE_STRING, &name,
                              DBUS_TYPE_INVALID))
    return FALSE;

  _dbus_string_init_const (&service_name, name);

  if (!_dbus_validate_bus_name (&service_name, 0,
                                _dbus_string_get_length (&service_name)))
    {
      dbus_set_error (error, DBUS_ERROR_INVALID_ARGS,
                      "Given bus name \"%s\" is not valid",
                      _dbus_string_get_const_data (&service_name));

      _dbus_verbose ("Attempt to release invalid service name\n");
      return FALSE;
    }

  if (_dbus_string_get_byte (&service_name, 0) == ':')
    {
      /* Not allowed; the base service name cannot be created or released */
      dbus_set_error (error, DBUS_ERROR_INVALID_ARGS,
                      "Cannot release a service starting with ':' such as \"%s\"",
                      _dbus_string_get_const_data (&service_name));

      _dbus_verbose ("Attempt to release invalid base service name \"%s\"",
                     _dbus_string_get_const_data (&service_name));
      return FALSE;
    }

   if (_dbus_string_equal_c_str (&service_name, DBUS_SERVICE_DBUS))
    {
      /* Not allowed; the base service name cannot be created or released */
      dbus_set_error (error, DBUS_ERROR_INVALID_ARGS,
                      "Cannot release the %s service because it is owned by the bus",
                     DBUS_SERVICE_DBUS);

      _dbus_verbose ("Attempt to release service name \"%s\"",
                     DBUS_SERVICE_DBUS);
      return FALSE;
    }

    *result = release_kdbus_name(transport, name);
    if (*result < 0)
      {
        dbus_set_error (error, DBUS_ERROR_FAILED , "Name \"%s\" could not be released, %d, %m", name, errno);
        return FALSE;
      }

    return TRUE;
}

/**
 * Checks if sender string is a unique name or well known name.
 *
 * @param sender - sender string
 * @param id - return pointer for sender id
 * @returns 1 if sender is unique id, returns 0 if well-known name and -1 on error
 */
static int
parse_sender(const char *sender,
             __u64      *id)
{
  char *endptr;
  /* if name is unique name it must be converted to unique id */
  if(strncmp(sender, ":1.", 3) == 0)
    {
      *id = strtoull(&sender[3], &endptr, 10);
      if (*id == 0 || *endptr != '\0' || errno ==  ERANGE)
        return -1;
      else
        return 1;
    }
  else
    return 0;  //well known name
}

/**
 * Adds a match rule to match broadcast messages going through the message bus.
 * Do no affect messages addressed directly.
 *
 * copied a lot from systemd bus_add_match_internal_kernel()
 *
 * TODO add error reporting
 *
 * @param transport transport
 * @param match rule
 */
static dbus_bool_t
add_match_kdbus (DBusTransportKdbus *transport,
                 MatchRule     *rule)
{
  struct kdbus_cmd_match    *msg;
  struct kdbus_item         *item;
  int         i, sender = -1;
  int         sender_size = 0;
  __u64       bloom_size;
  __u64       rule_cookie;
  __u64       src_id = KDBUS_MATCH_ID_ANY;
  uint64_t    msg_size;
  uint64_t    *bloom;
  dbus_bool_t need_bloom = FALSE;
  dbus_bool_t standard_rule_also = TRUE;
  char        argument_buf[sizeof("arg")-1 + 2 + sizeof("-slash-prefix") +1];

  rule_cookie = match_rule_get_cookie(rule);

/*
 * First check if it is org.freedesktop.DBus's NameOwnerChanged or any
 * org.freedesktop.DBus combination that includes this,
 * because it must be converted to special kdbus rule (kdbus has separate rules
 * for kdbus(kernel) generated broadcasts).
 */
  if ((rule->flags & MATCH_MEMBER) && strcmp(rule->member, "NameOwnerChanged"))
    goto standard_rule;
  if ((rule->flags & MATCH_MESSAGE_TYPE) && (rule->message_type != DBUS_MESSAGE_TYPE_SIGNAL))
    goto standard_rule;
  if(rule->flags & MATCH_SENDER)
    {
      sender = parse_sender(rule->sender, &src_id);
      if(sender < 0)
        return FALSE;
      if(sender == 0)
        {
          if (strcmp(rule->sender, DBUS_SERVICE_DBUS))
            goto standard_rule;
          else
            standard_rule_also = FALSE;
        }

      if(sender > 0)
        {
          if(transport->daemon_unique_name)
            {
              __u64 daemonsId;

              daemonsId = strtoull(&transport->daemon_unique_name[3], NULL, 10);
              if (src_id != daemonsId)
                goto standard_rule;
              else
                standard_rule_also = FALSE;
            }
        }
    }
  if (rule->flags & MATCH_INTERFACE)
    {
      if(strcmp(rule->interface, DBUS_INTERFACE_DBUS))
        goto standard_rule;
      else
        standard_rule_also = FALSE;
    }
  if (rule->flags & MATCH_PATH)
    {
      if(strcmp(rule->path, DBUS_PATH_DBUS))
        goto standard_rule;
      else
        standard_rule_also = FALSE;
    }

  //now we have to add kdbus rules related to well-known names
  msg_size = KDBUS_ALIGN8(offsetof(struct kdbus_cmd_match, items) +
       offsetof(struct kdbus_item, name_change) +
       offsetof(struct kdbus_notify_name_change, name));

  msg = alloca(msg_size);
  if(msg == NULL)
    {
      errno = ENOMEM;
      return FALSE;
    }

  msg->cookie = rule_cookie;
  msg->size = msg_size;

  /* first match against any name change */
  item = msg->items;
  item->size =
       offsetof(struct kdbus_item, name_change) +
       offsetof(struct kdbus_notify_name_change, name);  //TODO name from arg0 can be added here (if present in the rule)
  item->name_change.old.id = KDBUS_MATCH_ID_ANY;  //TODO can be replaced with arg0 or arg1 from rule (if present)
  item->name_change.new.id = KDBUS_MATCH_ID_ANY;  //TODO can be replaced with arg0 or arg2 from rule (if present)

  item->type = KDBUS_ITEM_NAME_CHANGE;
   if(ioctl(transport->fd, KDBUS_CMD_MATCH_ADD, msg))
     {
       _dbus_verbose("Failed adding match rule for name changes for daemon, error: %d, %m\n", errno);
       return FALSE;
     }

   /* then match against any name add */
   item->type = KDBUS_ITEM_NAME_ADD;
   if(ioctl(transport->fd, KDBUS_CMD_MATCH_ADD, msg))
     {
       _dbus_verbose("Failed adding match rule for name adding for daemon, error: %d, %m\n", errno);
       return FALSE;
     }

   /* then match against any name remove */
   item->type = KDBUS_ITEM_NAME_REMOVE;
   if(ioctl(transport->fd, KDBUS_CMD_MATCH_ADD, msg))
     {
       _dbus_verbose("Failed adding match rule for name removal for daemon, error: %d, %m\n", errno);
       return FALSE;
     }

   //now we add kdbus rules related to unique names
   msg_size = KDBUS_ALIGN8(offsetof(struct kdbus_cmd_match, items) +
       offsetof(struct kdbus_item, id_change) +
       sizeof(struct kdbus_notify_id_change));

   msg = alloca(msg_size);
   if(msg == NULL)
     {
       errno = ENOMEM;
       return FALSE;
     }

   msg->cookie = rule_cookie;
   msg->size = msg_size;

   item = msg->items;
   item->size =
       offsetof(struct kdbus_item, id_change) +
       sizeof(struct kdbus_notify_id_change);
   item->id_change.id = KDBUS_MATCH_ID_ANY; //TODO can be replaced with arg0 or arg1 or arg2 from rule (if present and applicable)

   item->type = KDBUS_ITEM_ID_ADD;
   if(ioctl(transport->fd, KDBUS_CMD_MATCH_ADD, msg))
     {
       _dbus_verbose("Failed adding match rule for adding id for daemon, error: %d, %m\n", errno);
       return FALSE;
     }

   item->type = KDBUS_ITEM_ID_REMOVE;
   if(ioctl(transport->fd, KDBUS_CMD_MATCH_ADD, msg))
     {
       _dbus_verbose("Failed adding match rule for id removal for daemon, error: %d, %m\n", errno);
       return FALSE;
     }

   _dbus_verbose("Added match rule for kernel correctly.\n");

   if(standard_rule_also == FALSE)
     return TRUE;


  /*
   * standard rule - registered in general way, for non-kernel broadcasts
   * kdbus don't use it to check kdbus(kernel) generated broadcasts
   */
standard_rule:
  bloom_size = transport->bloom.size;
  bloom = alloca(bloom_size);
  if(bloom == NULL)
    return FALSE;
  memset(bloom, 0, bloom_size);

  msg_size = sizeof(struct kdbus_cmd_match);

  if (rule->flags & MATCH_MESSAGE_TYPE)
  {
    bloom_add_pair(bloom, &transport->bloom, "message-type", dbus_message_type_to_string(rule->message_type));
    _dbus_verbose("Adding type %s \n", dbus_message_type_to_string(rule->message_type));
  }

  if(rule->flags & MATCH_SENDER)
    {
      sender = parse_sender(rule->sender, &src_id);
      if(sender < 0)
        return FALSE;

      if(sender > 0) // unique_id
          msg_size += KDBUS_ITEM_SIZE(sizeof(uint64_t));
      else // well-known name
        {
          sender_size = strlen(rule->sender) + 1;
          msg_size += KDBUS_ITEM_SIZE(sender_size);
        }
    }

  if (rule->flags & MATCH_INTERFACE)
    {
      bloom_add_pair(bloom, &transport->bloom, "interface", rule->interface);
      need_bloom = TRUE;
      _dbus_verbose("Adding interface %s \n", rule->interface);
    }

  if (rule->flags & MATCH_MEMBER)
  {
    bloom_add_pair(bloom, &transport->bloom, "member", rule->member);
    need_bloom = TRUE;
    _dbus_verbose("Adding member %s \n", rule->member);
  }

  if (rule->flags & MATCH_PATH)
  {
    bloom_add_pair(bloom, &transport->bloom, "path", rule->path);
    need_bloom = TRUE;
    _dbus_verbose("Adding path %s \n", rule->path);
  }

  if (rule->flags & MATCH_PATH_NAMESPACE)
  {
    bloom_add_pair(bloom, &transport->bloom, "path-slash-prefix", rule->path);
    need_bloom = TRUE;
    _dbus_verbose("Adding path-slash-prefix %s \n", rule->path);
  }

  for (i = 0; i < rule->args_len; i++)
    {
      if (rule->args[i] != NULL)
        {
          if(rule->arg_lens[i] & MATCH_ARG_IS_PATH)
            {
              sprintf(argument_buf, "arg%d-slash-prefix", i);
              bloom_add_prefixes(bloom, &transport->bloom, argument_buf, rule->args[i], '/');
            }
          else if (rule->arg_lens[i] & MATCH_ARG_NAMESPACE)
            {
              sprintf(argument_buf, "arg%d-dot-prefix", i);
              bloom_add_prefixes(bloom, &transport->bloom, argument_buf, rule->args[i], '.');
            }
          else
            {
              sprintf(argument_buf, "arg%d", i);
              bloom_add_pair(bloom, &transport->bloom, argument_buf, rule->args[i]);
            }
          need_bloom = TRUE;
        }
    }

  if(need_bloom)
    msg_size += KDBUS_ITEM_HEADER_SIZE + bloom_size;

  msg = alloca(msg_size);
  if(msg == NULL)
    return FALSE;

  msg->cookie = rule_cookie;
  msg->size = msg_size;
  item = msg->items;

  if(!sender)
    {
      item->type = KDBUS_ITEM_NAME;
      item->size = KDBUS_ITEM_HEADER_SIZE + sender_size;
      memcpy(item->str, rule->sender, sender_size);
      item = KDBUS_ITEM_NEXT(item);
      _dbus_verbose("Adding sender %s \n", rule->sender);
    }

  if(src_id != KDBUS_MATCH_ID_ANY)
    {
      item->type = KDBUS_ITEM_ID;
      item->size = KDBUS_ITEM_HEADER_SIZE + sizeof(__u64);
      item->id = src_id;
      item = KDBUS_ITEM_NEXT(item);
      _dbus_verbose("Adding src_id %llu \n", (unsigned long long)src_id);
    }

  if(need_bloom)
    {
      item->type = KDBUS_ITEM_BLOOM_MASK;
      item->size = KDBUS_ITEM_HEADER_SIZE + bloom_size;
      memcpy(item->data, bloom, bloom_size);
    }

  if(ioctl(transport->fd, KDBUS_CMD_MATCH_ADD, msg))
    {
      _dbus_verbose("Failed adding match bus rule cookie %llu,\nerror: %d, %m\n", rule_cookie, errno);
      return FALSE;
    }

  _dbus_verbose("Added match bus rule %llu\n", rule_cookie);
  return TRUE;
}

/**
 * Looks over messages sent to org.freedesktop.DBus. Hello message, which performs
 * registration on the bus, is captured as it must be locally converted into
 * appropriate ioctl. AddMatch and RemoveMatch are captured to store match rules
 * locally in case of false positive result of kdbus bloom filters, but after
 * being read they are passed to org.freedesktop.DBus to register these rules
 * in kdbus.
 * All the rest org.freedesktop.DBus methods are left untouched
 * and they are sent to dbus-daemon in the same way as every other messages.
 *
 * @param transport Transport
 * @param message Message being sent.
 * @returns 1 if message is not captured and should be passed to daemon
 *      0 if message was handled locally and correctly (it includes proper return of error reply),
 *     -1 message to org.freedesktop.DBus was not handled correctly.
 */
static int
capture_org_freedesktop_DBus(DBusTransportKdbus *transport,
                             const char         *destination,
                             DBusMessage        *message)
{
#if !defined(KDBUS_NOT_FOR_DAEMON)
  if(transport->my_kdbus_id)  //we can not ask for daemon's id until we perform Hello
    {
      int timeout = 300;

      while (transport->daemon_unique_name == NULL)
        {
          struct nameInfo info;

          if(!kdbus_NameQuery(DBUS_SERVICE_DBUS, &transport->base, &info))
            {
              free(info.sec_label);
              if(asprintf(&(transport->daemon_unique_name), ":1.%020llu", (unsigned long long)info.uniqueId) < 0)
                return -1;
              break;
            }

          if(timeout)
            timeout--;
          else
            {
              _dbus_verbose("DBus daemon's (org.freedesktop.DBus) unique name not found");
              errno = ENODEV;
              return -1;
            }
          usleep(100000);
        }
    }

  if(!strcmp(destination, DBUS_SERVICE_DBUS) || !strcmp(destination, transport->daemon_unique_name))
#else
  if(!strcmp(destination, DBUS_SERVICE_DBUS))
#endif
    {
      if(!strcmp(dbus_message_get_interface(message), DBUS_INTERFACE_DBUS))
        {
          if(!strcmp(dbus_message_get_member(message), "Hello"))
            {
              DBusMessageIter args;
              dbus_uint32_t registration_flags = 0;
              DBusError error;
              int ret = 0;

              dbus_message_iter_init(message, &args);
              if (dbus_message_iter_get_arg_type(&args) == DBUS_TYPE_UINT32)
                dbus_message_iter_get_basic(&args, &registration_flags);

              dbus_error_init(&error);
              if(!bus_register_kdbus(transport, registration_flags, &error))
                goto out;

              if(!reply_1_data(message, DBUS_TYPE_STRING, &transport->my_DBus_unique_name, transport->base.connection))
                return 0;  //on success we can not free name

              out:
              if(reply_with_error((char*)error.name, NULL, error.message, message, transport->base.connection))
                ret = -1;
              dbus_error_free(&error);
              free(transport->my_DBus_unique_name);
              return ret;
            }
#if defined(POLICY_IN_LIB) && !defined(REMOVE_POLICY_FROM_DAEMON)
          else if(!policy_check_can_send(transport->policy, message))
            {
              if (send_local_cant_send_error(transport, message) == FALSE)
                return -1;
              return 0;
            }
#endif
          else if(!strcmp(dbus_message_get_member(message), "RequestName"))
            {
              DBusError error;
              int result, ret = 0;

              dbus_error_init(&error);
              if(!request_DBus_name(&transport->base, message, &result, &error))
                {
                  if(reply_with_error((char*)error.name, NULL, error.message, message, transport->base.connection))
                    ret = -1;
                  dbus_error_free(&error);
                  return ret;
                }

              return reply_1_data(message, DBUS_TYPE_UINT32, &result, transport->base.connection);
            }
          else if(!strcmp(dbus_message_get_member(message), "ReleaseName"))
            {
              DBusError error;
              int result, ret = 0;

              dbus_error_init(&error);
              if(!release_DBus_name(&transport->base, message, &result, &error))
                {
                  if(reply_with_error((char*)error.name, NULL, error.message, message, transport->base.connection))
                    ret = -1;
                  dbus_error_free(&error);
                  return ret;
                }

              return reply_1_data(message, DBUS_TYPE_UINT32, &result, transport->base.connection);
            }
          else if(!strcmp(dbus_message_get_member(message), "AddMatch"))
            {
              const char *arg;
              DBusString arg_str;
              DBusError error;
              MatchRule *rule = NULL;
              DBusTransport *upper_transport = &transport->base;
              int ret = 0;

              dbus_error_init(&error);

              if (!dbus_message_get_args (message, &error,
                                          DBUS_TYPE_STRING, &arg,
                                          DBUS_TYPE_INVALID))
                goto failed;

              _dbus_string_init_const (&arg_str, arg);

              rule = match_rule_parse (upper_transport->connection, &arg_str, &error);
              if (rule == NULL)
                goto failed;

              if (!matchmaker_add_rule (transport->matchmaker, rule))
                {
                  dbus_set_error_const (&error, DBUS_ERROR_NO_MEMORY, "No memory to store match rule");
                  goto failed;
                }

              if(!add_match_kdbus (transport, rule))
                {
                  dbus_set_error (&error, _dbus_error_from_errno (errno), "Could not add match rule, %s",
                      _dbus_strerror_from_errno ());
                  goto failed;
                }

              match_rule_unref (rule);
              return reply_ack(message, upper_transport->connection);

            failed:
              if(rule)
                match_rule_unref (rule);
              _dbus_verbose("Error during AddMatch in lib: %s, %s\n", error.name, error.message);
              if(reply_with_error((char*)error.name, NULL, error.message, message, transport->base.connection))
                ret = -1;
              dbus_error_free(&error);
              return ret;
            }
          else if(!strcmp(dbus_message_get_member(message), "RemoveMatch"))
            {
              const char *arg;
              DBusString arg_str;
              DBusError error;
              MatchRule *rule = NULL;
              DBusTransport *upper_transport = &transport->base;
              int ret = 0;

              dbus_error_init(&error);

              if (!dbus_message_get_args (message, &error,
                                          DBUS_TYPE_STRING, &arg,
                                          DBUS_TYPE_INVALID))
                  goto failed_remove;

              _dbus_string_init_const (&arg_str, arg);

              rule = match_rule_parse (upper_transport->connection, &arg_str, &error);
              if (rule == NULL)
                goto failed_remove;

              if (!kdbus_remove_match (upper_transport, matchmaker_get_rules_list (transport->matchmaker, rule),
                                       transport->my_DBus_unique_name, rule, &error))
                goto failed_remove;

              if (!matchmaker_remove_rule_by_value (transport->matchmaker, rule, &error))
                goto failed_remove;

              match_rule_unref (rule);
              return reply_ack(message, upper_transport->connection);

            failed_remove:
              if (rule)
                match_rule_unref (rule);
              _dbus_verbose("Error during RemoveMatch in lib: %s, %s\n", error.name, error.message);
              if(reply_with_error((char*)error.name, NULL, error.message, message, transport->base.connection))
                ret = -1;
              dbus_error_free(&error);
              return ret;
            }
        }
    }

  return 1;  //send message to daemon
}

#if KDBUS_MSG_DECODE_DEBUG == 1
static const char
*msg_id(uint64_t id)
{
  char buf[64];
  const char* const_ptr;

  if (id == 0)
    return "KERNEL";
  if (id == ~0ULL)
    return "BROADCAST";

  sprintf(buf, "%llu", (unsigned long long)id);

  const_ptr = buf;
  return const_ptr;
}
#endif
struct kdbus_enum_table {
  long long id;
  const char *name;
};
#define _STRINGIFY(x) #x
#define STRINGIFY(x) _STRINGIFY(x)
#define ELEMENTSOF(x) (sizeof(x)/sizeof((x)[0]))
#define TABLE(what) static struct kdbus_enum_table kdbus_table_##what[]
#define ENUM(_id) { .id=_id, .name=STRINGIFY(_id) }
#define LOOKUP(what)                              \
  const char *enum_##what(long long id) {         \
  size_t i;                                       \
  for (i = 0; i < ELEMENTSOF(kdbus_table_##what); i++)  \
    if (id == kdbus_table_##what[i].id)           \
      return kdbus_table_##what[i].name;          \
    return "UNKNOWN";                             \
  }
const char *enum_MSG(long long id);
TABLE(MSG) = {
  ENUM(_KDBUS_ITEM_NULL),
  ENUM(KDBUS_ITEM_PAYLOAD_VEC),
  ENUM(KDBUS_ITEM_PAYLOAD_OFF),
  ENUM(KDBUS_ITEM_PAYLOAD_MEMFD),
  ENUM(KDBUS_ITEM_FDS),
  ENUM(KDBUS_ITEM_BLOOM_PARAMETER),
  ENUM(KDBUS_ITEM_BLOOM_FILTER),
  ENUM(KDBUS_ITEM_DST_NAME),
  ENUM(KDBUS_ITEM_CREDS),
  ENUM(KDBUS_ITEM_PID_COMM),
  ENUM(KDBUS_ITEM_TID_COMM),
  ENUM(KDBUS_ITEM_EXE),
  ENUM(KDBUS_ITEM_CMDLINE),
  ENUM(KDBUS_ITEM_CGROUP),
  ENUM(KDBUS_ITEM_CAPS),
  ENUM(KDBUS_ITEM_SECLABEL),
  ENUM(KDBUS_ITEM_AUDIT),
  ENUM(KDBUS_ITEM_CONN_NAME),
  ENUM(KDBUS_ITEM_NAME),
  ENUM(KDBUS_ITEM_TIMESTAMP),
  ENUM(KDBUS_ITEM_NAME_ADD),
  ENUM(KDBUS_ITEM_NAME_REMOVE),
  ENUM(KDBUS_ITEM_NAME_CHANGE),
  ENUM(KDBUS_ITEM_ID_ADD),
  ENUM(KDBUS_ITEM_ID_REMOVE),
  ENUM(KDBUS_ITEM_REPLY_TIMEOUT),
  ENUM(KDBUS_ITEM_REPLY_DEAD),
};
LOOKUP(MSG);
const char *enum_PAYLOAD(long long id);
TABLE(PAYLOAD) = {
  ENUM(KDBUS_PAYLOAD_KERNEL),
  ENUM(KDBUS_PAYLOAD_DBUS),
};
LOOKUP(PAYLOAD);

static dbus_uint32_t
get_next_client_serial (DBusTransportKdbus *transport)
{
  dbus_uint32_t serial;

  serial = transport->client_serial++;

  if (transport->client_serial == 0)
    transport->client_serial = 1;

  return serial;
}

/**
 * Finalizes locally generated DBus message
 * and puts it into data buffer.
 *
 * @param message Message to load.
 * @param data Place to load message.
 * @returns Size of message loaded.
 */
static int
put_message_into_data(DBusMessage *message,
                      char        *data)
{
  int ret_size;
  const DBusString *header;
  const DBusString *body;
  int size;

  dbus_message_lock (message);
  _dbus_message_get_network_data (message, &header, &body);
  ret_size = _dbus_string_get_length(header);
  memcpy(data, _dbus_string_get_const_data(header), ret_size);
  data += ret_size;
  size = _dbus_string_get_length(body);
  memcpy(data, _dbus_string_get_const_data(body), size);
  ret_size += size;

  return ret_size;
}

/**
 * Calculates length of the kdbus message content (payload).
 *
 * @param msg kdbus message
 * @return the length of the kdbus message's payload.
 */
static int
kdbus_message_size(const struct kdbus_msg* msg)
{
  const struct kdbus_item *item;
  int ret_size = 0;

  KDBUS_ITEM_FOREACH(item, msg, items)
    {
      if (item->size < KDBUS_ITEM_HEADER_SIZE)
        {
          _dbus_verbose("  +%s (%llu bytes) invalid data record\n", enum_MSG(item->type), item->size);
          return -1;
        }
      switch (item->type)
        {
          case KDBUS_ITEM_PAYLOAD_OFF:
            ret_size += item->vec.size;
            break;
          case KDBUS_ITEM_PAYLOAD_MEMFD:
            ret_size += item->memfd.size;
            break;
          default:
            break;
        }
    }

  return ret_size;
}

static int
generate_NameSignal(const char *signal,
                    const char *name,
                    char *data,
                    DBusTransportKdbus *transport)
{
  DBusMessage *message;

  _dbus_verbose ("Generating %s for %s.\n", signal, name);

  message = dbus_message_new_signal (DBUS_PATH_DBUS, DBUS_INTERFACE_DBUS, signal);
  if (message == NULL)
    return -1;

  if (!dbus_message_append_args (message, DBUS_TYPE_STRING, &name, DBUS_TYPE_INVALID))
    goto error;
  if (!dbus_message_set_destination (message, transport->my_DBus_unique_name))
    goto error;
  if (!dbus_message_set_sender(message, DBUS_SERVICE_DBUS))
    goto error;
  dbus_message_set_serial(message, get_next_client_serial(transport));

  int ret =  put_message_into_data(message, data);
  dbus_message_unref (message);
  return ret;

  error:
    dbus_message_unref (message);
    return -1;
}

/*
 * The NameOwnerChanged signals take three parameters with
 * unique or well-known names, but only some forms actually
 * exist:
 *
 * WELLKNOWN, "", UNIQUE       → KDBUS_ITEM_NAME_ADD
 * WELLKNOWN, UNIQUE, ""       → KDBUS_ITEM_NAME_REMOVE
 * WELLKNOWN, UNIQUE, UNIQUE   → KDBUS_ITEM_NAME_CHANGE
 * UNIQUE, "", UNIQUE          → KDBUS_ITEM_ID_ADD
 * UNIQUE, UNIQUE, ""          → KDBUS_ITEM_ID_REMOVE
 *
 * For the latter two the two unique names must be identical.
 */
static int
kdbus_handle_name_owner_changed(char       *data,
                                __u64       type,
                                const char *bus_name,
                                __u64       old,
                                __u64       new,
                                dbus_uint32_t serial)
{
  DBusMessage *message = NULL;
  DBusMessageIter args;
  char  tmp_str[128];
  const char *const_ptr;
  int ret = -1;

  if((message = dbus_message_new_signal(DBUS_PATH_DBUS, DBUS_INTERFACE_DBUS, "NameOwnerChanged")) == NULL)
    goto error;

  dbus_message_iter_init_append(message, &args);

  // for ID_ADD and ID_REMOVE this function takes NULL as bus_name
  if(bus_name == NULL)
    {
      sprintf(tmp_str,":1.%020llu", old != 0 ? old : new);
      const_ptr = tmp_str;
    }
  else
    const_ptr = bus_name;

  dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &const_ptr);

  _dbus_verbose("%s\n", const_ptr);


  if ((old==0) && (new==0)) {
    /* kdbus generates its own set of events that can not be passed to
     * client without translation. */
    const char *src = "org.freedesktop.DBus";
    const char *dst = "org.freedesktop.DBus";



    if (type == KDBUS_ITEM_NAME_ADD || type == KDBUS_ITEM_ID_ADD)
      src = "";
    else if (type == KDBUS_ITEM_NAME_REMOVE || type == KDBUS_ITEM_ID_REMOVE)
      dst = "";

    dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &src);
    dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &dst);


    _dbus_verbose("[NameOwnerChanged:%s, old=%lld, new=%lld\n", __func__, old, new);
    goto finish;
  }

  // determine and append old_id
  if(old != 0)
    {
      sprintf(tmp_str,":1.%020llu", old);
      const_ptr = tmp_str;
    }
  else
    const_ptr = "";


  dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &const_ptr);
  _dbus_verbose("%s\n", const_ptr);
  // determine and append new_id
  if(new != 0)
    {
      sprintf(tmp_str,":1.%020llu", new);
      const_ptr = tmp_str;
    }
  else
    const_ptr = "";

  dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &const_ptr);
  _dbus_verbose("%s\n", const_ptr);

  finish:

  dbus_message_set_sender(message, DBUS_SERVICE_DBUS);
  dbus_message_set_serial(message, serial);

  ret = put_message_into_data(message, data);
  dbus_message_unref(message);
  return ret;

  error:
  if(message)
    dbus_message_unref(message);

  return -1;
}


/**
 * Decodes kdbus message in order to extract DBus message and puts it into received data buffer
 * and file descriptor's buffer. Also captures kdbus error messages and kdbus kernel broadcasts
 * and converts all of them into appropriate DBus messages.
 *
 * @param msg kdbus message
 * @param data place to copy DBus message to
 * @param kdbus_transport transport
 * @param fds place to store file descriptors received
 * @param n_fds place to store quantity of file descriptors received
 * @return number of DBus message's bytes received or -1 on error
 */
static int
kdbus_decode_msg(const struct kdbus_msg *msg,
                 char                   *data,
                 DBusTransportKdbus     *kdbus_transport,
                 int                    *fds,
                 int                    *n_fds)
{
  const struct kdbus_item *item;
  int ret_size = 0;

#if KDBUS_MSG_DECODE_DEBUG == 1
  _dbus_verbose("MESSAGE: %s (%llu bytes) flags=0x%llx, %s → %s, cookie=%llu, timeout=%llu\n",
                enum_PAYLOAD(msg->payload_type),
                (unsigned long long) msg->size,
                (unsigned long long) msg->flags,
                msg_id(msg->src_id),
                msg_id(msg->dst_id),
                (unsigned long long) msg->cookie,
                (unsigned long long) msg->timeout_ns);
#endif

  *n_fds = 0;

  KDBUS_ITEM_FOREACH(item, msg, items)
  {
    if (item->size < KDBUS_ITEM_HEADER_SIZE)
      {
        _dbus_verbose("  +%s (%llu bytes) invalid data record\n", enum_MSG(item->type), item->size);
        ret_size = -1;
        break;
      }

    switch (item->type)
      {
        case KDBUS_ITEM_PAYLOAD_OFF:
          memcpy(data, (char *)msg+item->vec.offset, item->vec.size);
          data += item->vec.size;
          ret_size += item->vec.size;

          _dbus_verbose("  +%s (%llu bytes) off=%llu size=%llu\n",
              enum_MSG(item->type), item->size,
              (unsigned long long)item->vec.offset,
              (unsigned long long)item->vec.size);
          break;

        case KDBUS_ITEM_PAYLOAD_MEMFD:
          {
            char *buf;
            uint64_t size;

            size = item->memfd.size;
            _dbus_verbose("memfd.size : %llu\n", (unsigned long long)size);

            buf = mmap(NULL, size, PROT_READ , MAP_SHARED, item->memfd.fd, 0);
            if (buf == MAP_FAILED)
              {
                _dbus_verbose("mmap() fd=%i failed:%m", item->memfd.fd);
                return -1;
              }

            memcpy(data, buf, size);
            data += size;
            ret_size += size;

            munmap(buf, size);
            close(item->memfd.fd);

            _dbus_verbose("  +%s (%llu bytes) off=%llu size=%llu\n",
                enum_MSG(item->type), item->size,
                (unsigned long long)item->vec.offset,
                (unsigned long long)item->vec.size);
            break;
          }

        case KDBUS_ITEM_FDS:
          {
            int i;

            *n_fds = (item->size - KDBUS_ITEM_HEADER_SIZE) / sizeof(int);
            memcpy(fds, item->fds, *n_fds * sizeof(int));
            for (i = 0; i < *n_fds; i++)
              _dbus_fd_set_close_on_exec(fds[i]);
            break;
          }

    #if KDBUS_MSG_DECODE_DEBUG == 1
        case KDBUS_ITEM_CREDS:
          _dbus_verbose("  +%s (%llu bytes) uid=%lld, gid=%lld, pid=%lld, tid=%lld, starttime=%lld\n",
                        enum_MSG(item->type), item->size,
                        item->creds.uid, item->creds.gid,
                        item->creds.pid, item->creds.tid,
                        item->creds.starttime);
          break;

        case KDBUS_ITEM_PID_COMM:
        case KDBUS_ITEM_TID_COMM:
        case KDBUS_ITEM_EXE:
        case KDBUS_ITEM_CGROUP:
        case KDBUS_ITEM_SECLABEL:
        case KDBUS_ITEM_DST_NAME:
          _dbus_verbose("  +%s (%llu bytes) '%s' (%zu)\n",
                        enum_MSG(item->type), item->size, item->str, strlen(item->str));
          break;

        case KDBUS_ITEM_CMDLINE:
        case KDBUS_ITEM_NAME: {
          __u64 size = item->size - KDBUS_ITEM_HEADER_SIZE;
          const char *str = item->str;
          int count = 0;

          _dbus_verbose("  +%s (%llu bytes) ", enum_MSG(item->type), item->size);
          while (size)
            {
              _dbus_verbose("'%s' ", str);
              size -= strlen(str) + 1;
              str += strlen(str) + 1;
              count++;
            }

          _dbus_verbose("(%d string%s)\n", count, (count == 1) ? "" : "s");
          break;
        }

        case KDBUS_ITEM_AUDIT:
          _dbus_verbose("  +%s (%llu bytes) loginuid=%llu sessionid=%llu\n",
                        enum_MSG(item->type), item->size,
                        (unsigned long long)item->data64[0],
                        (unsigned long long)item->data64[1]);
          break;

        case KDBUS_ITEM_CAPS: {
          int n;
          const uint32_t *cap;
          int i;

          _dbus_verbose("  +%s (%llu bytes) len=%llu bytes)\n",
              enum_MSG(item->type), item->size,
              (unsigned long long)item->size - KDBUS_ITEM_HEADER_SIZE);

          cap = item->data32;
          n = (item->size - KDBUS_ITEM_HEADER_SIZE) / 4 / sizeof(uint32_t);

          _dbus_verbose("    CapInh=");
          for (i = 0; i < n; i++)
            _dbus_verbose("%08x", cap[(0 * n) + (n - i - 1)]);

          _dbus_verbose(" CapPrm=");
          for (i = 0; i < n; i++)
            _dbus_verbose("%08x", cap[(1 * n) + (n - i - 1)]);

          _dbus_verbose(" CapEff=");
          for (i = 0; i < n; i++)
            _dbus_verbose("%08x", cap[(2 * n) + (n - i - 1)]);

          _dbus_verbose(" CapInh=");
          for (i = 0; i < n; i++)
            _dbus_verbose("%08x", cap[(3 * n) + (n - i - 1)]);
          _dbus_verbose("\n");
          break;
        }

        case KDBUS_ITEM_TIMESTAMP:
          _dbus_verbose("  +%s (%llu bytes) realtime=%lluns monotonic=%lluns\n",
                        enum_MSG(item->type), item->size,
                        (unsigned long long)item->timestamp.realtime_ns,
                        (unsigned long long)item->timestamp.monotonic_ns);
          break;
    #endif

        case KDBUS_ITEM_REPLY_TIMEOUT:
        case KDBUS_ITEM_REPLY_DEAD:
          {
            DBusMessage *message = NULL;
            _dbus_verbose("  +%s (%llu bytes) cookie=%llu\n",
                          enum_MSG(item->type), item->size, msg->cookie_reply);

            message = generate_local_error_message(msg->cookie_reply,
                    item->type == KDBUS_ITEM_REPLY_TIMEOUT ? DBUS_ERROR_NO_REPLY : DBUS_ERROR_NAME_HAS_NO_OWNER, NULL);
            if(message == NULL)
              {
                ret_size = -1;
                goto out;
              }

            dbus_message_set_serial(message, get_next_client_serial(kdbus_transport));
            ret_size = put_message_into_data(message, data);
            if(message)
              {
                dbus_message_unref(message);
                message = NULL;
              }
          }
          break;

        case KDBUS_ITEM_NAME_ADD:
        case KDBUS_ITEM_NAME_REMOVE:
        case KDBUS_ITEM_NAME_CHANGE:
          {
            int local_ret;

            _dbus_verbose("  +%s (%llu bytes) '%s', old id=%lld, new id=%lld, old flags=0x%llx, new flags=0x%llx\n",
                          enum_MSG(item->type), (unsigned long long) item->size,
                          item->name_change.name, item->name_change.old.id,
                          item->name_change.new.id, item->name_change.old.flags,
                          item->name_change.new.flags);

            if(item->name_change.new.id == kdbus_transport->my_kdbus_id)
              {
                ret_size = generate_NameSignal("NameAcquired", item->name_change.name, data, kdbus_transport);
                data += ret_size;
              }
            else if(item->name_change.old.id == kdbus_transport->my_kdbus_id)
              {
                ret_size = generate_NameSignal("NameLost", item->name_change.name, data, kdbus_transport);
                data += ret_size;
              }

            if (ret_size == -1)
              goto out;


            if(item->name_change.new.flags & KDBUS_NAME_ACTIVATOR)
              local_ret = kdbus_handle_name_owner_changed(data,
                                                          item->type,
                                                         item->name_change.name,
                                                         item->name_change.old.id, 0,
                                                         get_next_client_serial(kdbus_transport));
            else if(item->name_change.old.flags & KDBUS_NAME_ACTIVATOR)
              local_ret = kdbus_handle_name_owner_changed(data,
                                                          item->type,
                                                         item->name_change.name, 0,
                                                         item->name_change.new.id,
                                                         get_next_client_serial(kdbus_transport));
            else
              local_ret = kdbus_handle_name_owner_changed(data,
                                                          item->type,
                                                         item->name_change.name,
                                                         item->name_change.old.id,
                                                         item->name_change.new.id,
                                                         get_next_client_serial(kdbus_transport));
            if (local_ret == -1)
              goto out;

            ret_size += local_ret;
          }
          break;

        case KDBUS_ITEM_ID_ADD:
        case KDBUS_ITEM_ID_REMOVE:
          _dbus_verbose("  +%s (%llu bytes) id=%llu flags=%llu\n",
                        enum_MSG(item->type), (unsigned long long) item->size,
                        (unsigned long long) item->id_change.id,
                        (unsigned long long) item->id_change.flags);

          if(item->id_change.flags & KDBUS_HELLO_ACTIVATOR)
            ret_size = kdbus_handle_name_owner_changed(data, item->type, NULL, 0, 0,
                       get_next_client_serial(kdbus_transport));
          else
            ret_size = kdbus_handle_name_owner_changed(data, item->type, NULL,
                       item->type == KDBUS_ITEM_ID_ADD ? 0 : item->id_change.id,
                       item->type == KDBUS_ITEM_ID_ADD ? item->id_change.id : 0,
                       get_next_client_serial(kdbus_transport));

          if (ret_size == -1)
            goto out;
          break;

#if KDBUS_MSG_DECODE_DEBUG == 1
        default:
          _dbus_verbose("  +%s (%llu bytes)\n", enum_MSG(item->type), item->size);
          break;
#endif
      }
  }

#if KDBUS_MSG_DECODE_DEBUG == 1

  if ((char *)item - ((char *)msg + msg->size) >= 8)
    _dbus_verbose("invalid padding at end of message\n");
#endif

  out:
  return ret_size;
}

/**
 * Reads message from kdbus and puts it into DBus buffers
 *
 * @param kdbus_transport transport
 * @param buffer place to copy received message to
 * @param fds place to store file descriptors received with the message
 * @param n_fds place to store quantity of file descriptors received
 * @return size of received message on success, -1 on error
 */
static int
kdbus_read_message(DBusTransportKdbus *kdbus_transport,
                   DBusString         *buffer,
                   int                *fds,
                   int                *n_fds)
{
  int ret_size, buf_size;
  struct kdbus_cmd_recv recv = {};
  struct kdbus_msg *msg;
  char *data;
  int start;

  start = _dbus_string_get_length (buffer);

  if(kdbus_transport->activator != NULL)
    recv.flags |= KDBUS_RECV_PEEK;

  again:
  if (ioctl(kdbus_transport->fd, KDBUS_CMD_MSG_RECV, &recv) < 0)
    {
      if(errno == EINTR)
        goto again;
      _dbus_verbose("kdbus error receiving message: %d (%m)\n", errno);
      _dbus_string_set_length (buffer, start);
      return -1;
    }

  msg = (struct kdbus_msg *)((char*)kdbus_transport->kdbus_mmap_ptr + recv.offset);

  buf_size = kdbus_message_size(msg);
  if (buf_size == -1)
    {
      _dbus_verbose("kdbus error - too short message: %d (%m)\n", errno);
      return -1;
    }

  /* What is the maximum size of the locally generated message?
     I just assume 2048 bytes */
  buf_size = MAX(buf_size, 2048);

  if (!_dbus_string_lengthen (buffer, buf_size))
    {
      errno = ENOMEM;
      return -1;
    }
  data = _dbus_string_get_data_len (buffer, start, buf_size);

  ret_size = kdbus_decode_msg(msg, data, kdbus_transport, fds, n_fds);

  if(ret_size == -1) /* error */
    {
      _dbus_string_set_length (buffer, start);
      return -1;
    }
  else if (buf_size != ret_size) /* case of locally generated message */
    {
      _dbus_string_set_length (buffer, start + ret_size);
    }

  if(kdbus_transport->activator != NULL)
    return ret_size;

  again2:
  if (ioctl(kdbus_transport->fd, KDBUS_CMD_FREE, &recv.offset) < 0)
    {
      if(errno == EINTR)
        goto again2;
      _dbus_verbose("kdbus error freeing message: %d (%m)\n", errno);
      return -1;
    }

  return ret_size;
}

/**
 * Copy-paste from socket transport. Only renames done.
 */
static void
free_watches (DBusTransport *transport)
{
  DBusTransportKdbus *kdbus_transport = (DBusTransportKdbus*) transport;

  _dbus_verbose ("start\n");

  if (kdbus_transport->read_watch)
    {
      if (transport->connection)
        _dbus_connection_remove_watch_unlocked (transport->connection,
                                                kdbus_transport->read_watch);
      _dbus_watch_invalidate (kdbus_transport->read_watch);
      _dbus_watch_unref (kdbus_transport->read_watch);
      kdbus_transport->read_watch = NULL;
    }

  if (kdbus_transport->write_watch)
    {
      if (transport->connection)
        _dbus_connection_remove_watch_unlocked (transport->connection,
                                                kdbus_transport->write_watch);
      _dbus_watch_invalidate (kdbus_transport->write_watch);
      _dbus_watch_unref (kdbus_transport->write_watch);
      kdbus_transport->write_watch = NULL;
    }

  _dbus_verbose ("end\n");
}

/**
 * Copy-paste from socket transport. Only done needed renames and removed
 * lines related to encoded messages.
 */
static void
transport_finalize (DBusTransport *transport)
{
  _dbus_verbose ("\n");

  free_watches (transport);

  _dbus_transport_finalize_base (transport);

  _dbus_assert (((DBusTransportKdbus*) transport)->read_watch == NULL);
  _dbus_assert (((DBusTransportKdbus*) transport)->write_watch == NULL);

  free_matchmaker(((DBusTransportKdbus*) transport)->matchmaker);

  free(((DBusTransportKdbus*) transport)->daemon_unique_name);

#if defined(POLICY_IN_LIB) && !defined(REMOVE_POLICY_FROM_DAEMON)
  if (((DBusTransportKdbus*) transport)->policy)
    dbus_policy_free (((DBusTransportKdbus*) transport)->policy);
#endif
  dbus_free (((DBusTransportKdbus*) transport)->activator);
  dbus_free (transport);
}

/**
 * Copy-paste from socket transport. Removed code related to authentication,
 * socket_transport replaced by kdbus_transport.
 */
static void
check_write_watch (DBusTransport *transport)
{
  DBusTransportKdbus *kdbus_transport = (DBusTransportKdbus*) transport;
  dbus_bool_t needed;

  if (transport->connection == NULL)
    return;

  if (transport->disconnected)
    {
      _dbus_assert (kdbus_transport->write_watch == NULL);
      return;
    }

  _dbus_transport_ref (transport);

  needed = _dbus_connection_has_messages_to_send_unlocked (transport->connection);

  _dbus_verbose ("check_write_watch(): needed = %d on connection %p watch %p fd = %d outgoing messages exist %d\n",
                 needed, transport->connection, kdbus_transport->write_watch,
                 kdbus_transport->fd,
                 _dbus_connection_has_messages_to_send_unlocked (transport->connection));

  _dbus_connection_toggle_watch_unlocked (transport->connection,
                                          kdbus_transport->write_watch,
                                          needed);

  _dbus_transport_unref (transport);
}

/**
 * Copy-paste from socket transport. Removed code related to authentication,
 * socket_transport replaced by kdbus_transport.
 */
static void
check_read_watch (DBusTransport *transport)
{
  DBusTransportKdbus *kdbus_transport = (DBusTransportKdbus*) transport;
  dbus_bool_t need_read_watch;

  _dbus_verbose ("fd = %d\n",kdbus_transport->fd);

  if (transport->connection == NULL)
    return;

  if (transport->disconnected)
    {
      _dbus_assert (kdbus_transport->read_watch == NULL);
      return;
    }

  _dbus_transport_ref (transport);

   need_read_watch =
      (_dbus_counter_get_size_value (transport->live_messages) < transport->max_live_messages_size) &&
      (_dbus_counter_get_unix_fd_value (transport->live_messages) < transport->max_live_messages_unix_fds);

  _dbus_verbose ("  setting read watch enabled = %d\n", need_read_watch);

  _dbus_connection_toggle_watch_unlocked (transport->connection,
                                          kdbus_transport->read_watch,
                                          need_read_watch);

  _dbus_transport_unref (transport);
}

/**
 * Copy-paste from socket transport.
 */
static void
do_io_error (DBusTransport *transport)
{
  _dbus_transport_ref (transport);
  _dbus_transport_disconnect (transport);
  _dbus_transport_unref (transport);
}

/**
 *  Based on do_writing from socket transport.
 *  Removed authentication code and code related to encoded messages
 *  and adapted to kdbus transport.
 *  In socket transport returns false on out-of-memory. Here this won't happen,
 *  so it always returns TRUE.
 */
static dbus_bool_t
do_writing (DBusTransport *transport)
{
  DBusTransportKdbus *kdbus_transport = (DBusTransportKdbus*) transport;
  int total = 0;
  dbus_bool_t oom = FALSE;

  if (transport->disconnected)
    {
      _dbus_verbose ("Not connected, not writing anything\n");
      return TRUE;
    }

  _dbus_verbose ("do_writing(), have_messages = %d, fd = %d\n",
  _dbus_connection_has_messages_to_send_unlocked (transport->connection), kdbus_transport->fd);

  while (!transport->disconnected && _dbus_connection_has_messages_to_send_unlocked (transport->connection))
    {
      int bytes_written;
      DBusMessage *message;
      const DBusString *header;
      const DBusString *body;
      int total_bytes_to_write;
      const char* pDestination;

      if (total > kdbus_transport->max_bytes_written_per_iteration)
        {
          _dbus_verbose ("%d bytes exceeds %d bytes written per iteration, returning\n",
                         total, kdbus_transport->max_bytes_written_per_iteration);
          goto out;
        }

      message = _dbus_connection_get_message_to_send (transport->connection);
      _dbus_assert (message != NULL);
      dbus_message_unlock(message);
#if defined(POLICY_IN_LIB) && !defined(REMOVE_POLICY_FROM_DAEMON)
      //don't set sender if previously preset (ex. error from policy)
      if (dbus_message_get_sender(message) == NULL)
#endif
      if(!dbus_message_set_sender(message, kdbus_transport->my_DBus_unique_name))
        {
          oom = TRUE;
          goto out;
        }
      dbus_message_lock (message);
      _dbus_message_get_network_data (message, &header, &body);
      total_bytes_to_write = _dbus_string_get_length(header) + _dbus_string_get_length(body);
      pDestination = dbus_message_get_destination(message);

      if(pDestination)
        {
          int ret;

          ret = capture_org_freedesktop_DBus((DBusTransportKdbus*)transport, pDestination, message);
          if(ret < 0)  //error
            {
              bytes_written = -1;
              goto written;
            }
          else if(ret == 0)  //hello message captured and handled correctly
            {
              bytes_written = total_bytes_to_write;
              goto written;
            }
          //else send as regular message
        }

      bytes_written = kdbus_write_msg(kdbus_transport, message, pDestination);

      written:
      if (bytes_written < 0)
        {
          if(errno == ENOMEM)
            {
              oom = TRUE;
              goto out;
            }

          /* EINTR already handled for us */

          /* For some discussion of why we also ignore EPIPE here, see
           * http://lists.freedesktop.org/archives/dbus/2008-March/009526.html
           */

          if (_dbus_get_is_errno_eagain_or_ewouldblock () || _dbus_get_is_errno_epipe ())
            goto out;
          else
            {
              _dbus_verbose ("Error writing to remote app: %s\n", _dbus_strerror_from_errno ());
//              do_io_error (transport);
              /*TODO the comment above may cause side effects, but must be removed here
               to not disconnect the connection. If side-effects appears, reporting errors for upper functions
               must be rearranged.*/
              goto out;
            }
        }
      else
        {
          _dbus_verbose (" wrote %d bytes of %d\n", bytes_written,
              total_bytes_to_write);

          total += bytes_written;

          _dbus_assert (bytes_written == total_bytes_to_write);

          _dbus_connection_message_sent_unlocked (transport->connection,
                  message);
        }
    }

out:
  if (oom)
    return FALSE;
  else
    return TRUE;
}

/**
 *  Based on do_reading from socket transport.
 *  Removed authentication code and code related to encoded messages
 *  and adapted to kdbus transport.
 *  returns false on out-of-memory
 */
static dbus_bool_t
do_reading (DBusTransport *transport)
{
  DBusTransportKdbus *kdbus_transport = (DBusTransportKdbus*) transport;
  DBusString *buffer;
  int bytes_read;
  dbus_bool_t oom = FALSE;
  int *fds, n_fds;
  int total = 0;

  _dbus_verbose ("fd = %d\n",kdbus_transport->fd);

 again:

  /* See if we've exceeded max messages and need to disable reading */
 if(kdbus_transport->activator == NULL)
  check_read_watch (transport);

  if (total > kdbus_transport->max_bytes_read_per_iteration)
    {
      _dbus_verbose ("%d bytes exceeds %d bytes read per iteration, returning\n",
                     total, kdbus_transport->max_bytes_read_per_iteration);
      goto out;
    }

  _dbus_assert (kdbus_transport->read_watch != NULL ||
                transport->disconnected);

  if (transport->disconnected)
    goto out;

  if (!dbus_watch_get_enabled (kdbus_transport->read_watch))
    return TRUE;

  if (!_dbus_message_loader_get_unix_fds(transport->loader, &fds, &n_fds))
  {
      _dbus_verbose ("Out of memory reading file descriptors\n");
      oom = TRUE;
      goto out;
  }
  _dbus_message_loader_get_buffer (transport->loader, &buffer);

  bytes_read = kdbus_read_message(kdbus_transport, buffer, fds, &n_fds);

  if (bytes_read >= 0 && n_fds > 0)
    _dbus_verbose("Read %i unix fds\n", n_fds);

  _dbus_message_loader_return_buffer (transport->loader,
                                      buffer);
  _dbus_message_loader_return_unix_fds(transport->loader, fds, bytes_read < 0 ? 0 : n_fds);

  if (bytes_read < 0)
    {
      /* EINTR already handled for us */

      if (_dbus_get_is_errno_enomem ())
        {
          _dbus_verbose ("Out of memory in read()/do_reading()\n");
          oom = TRUE;
          goto out;
        }
      else if (_dbus_get_is_errno_eagain_or_ewouldblock ())
        goto out;
      else
        {
          _dbus_verbose ("Error reading from remote app: %s\n",
                         _dbus_strerror_from_errno ());
          do_io_error (transport);
          goto out;
        }
    }
  else if (bytes_read == 0)
    {
      _dbus_verbose ("Disconnected from remote app\n");
      do_io_error (transport);
      goto out;
    }
  else
    {
      _dbus_verbose (" read %d bytes\n", bytes_read);

      total += bytes_read;

      if (!_dbus_transport_queue_messages (transport))
        {
          oom = TRUE;
          _dbus_verbose (" out of memory when queueing messages we just read in the transport\n");
          goto out;
        }

      /* Try reading more data until we get EAGAIN and return, or
       * exceed max bytes per iteration.  If in blocking mode of
       * course we'll block instead of returning.
       */
      goto again;
    }

 out:
  if (oom)
    return FALSE;
  return TRUE;
}

/**
 * Copy-paste from socket transport, with socket replaced by kdbus.
 */
static dbus_bool_t
unix_error_with_read_to_come (DBusTransport *itransport,
                              DBusWatch     *watch,
                              unsigned int   flags)
{
   DBusTransportKdbus *transport = (DBusTransportKdbus *) itransport;

   if (!((flags & DBUS_WATCH_HANGUP) || (flags & DBUS_WATCH_ERROR)))
      return FALSE;

  /* If we have a read watch enabled ...
     we -might have data incoming ... => handle the HANGUP there */
   if (watch != transport->read_watch && _dbus_watch_get_enabled (transport->read_watch))
      return FALSE;

   return TRUE;
}

/**
 *  Copy-paste from socket transport. Removed authentication related code
 *  and renamed socket_transport to kdbus_transport.
 */
static dbus_bool_t
kdbus_handle_watch (DBusTransport *transport,
                   DBusWatch     *watch,
                   unsigned int   flags)
{
  DBusTransportKdbus *kdbus_transport = (DBusTransportKdbus*) transport;

  _dbus_assert (watch == kdbus_transport->read_watch ||
                watch == kdbus_transport->write_watch);
  _dbus_assert (watch != NULL);

  /* If we hit an error here on a write watch, don't disconnect the transport yet because data can
   * still be in the buffer and do_reading may need several iteration to read
   * it all (because of its max_bytes_read_per_iteration limit).
   */
  if (!(flags & DBUS_WATCH_READABLE) && unix_error_with_read_to_come (transport, watch, flags))
    {
      _dbus_verbose ("Hang up or error on watch\n");
      _dbus_transport_disconnect (transport);
      return TRUE;
    }

  if (watch == kdbus_transport->read_watch &&
      (flags & DBUS_WATCH_READABLE))
    {
      _dbus_verbose ("handling read watch %p flags = %x\n",
                     watch, flags);

      if (!do_reading (transport))
        {
          _dbus_verbose ("no memory to read\n");
          return FALSE;
        }
    }
  else if (watch == kdbus_transport->write_watch &&
          (flags & DBUS_WATCH_WRITABLE))
    {
      _dbus_verbose ("handling write watch, have_outgoing_messages = %d\n",
                     _dbus_connection_has_messages_to_send_unlocked (transport->connection));

      if (!do_writing (transport))
        {
          _dbus_verbose ("no memory to write\n");
          return FALSE;
        }

      /* See if we still need the write watch */
      check_write_watch (transport);
    }

  return TRUE;
}

/**
 * Copy-paste from socket transport, but socket_transport renamed to kdbus_transport
 * and _dbus_close_socket replaced with close().
 */
static void
kdbus_disconnect (DBusTransport *transport)
{
  DBusTransportKdbus *kdbus_transport = (DBusTransportKdbus*) transport;

  _dbus_verbose ("\n");

  free_watches (transport);

  again:
   if (close (kdbus_transport->fd) < 0)
     {
       if (errno == EINTR)
         goto again;
     }
   kdbus_transport->fd = -1;

   if(kdbus_transport->kdbus_mmap_ptr == NULL) {
		   printf("libdbus:kdbus_transport->kdbus_mmap_ptr is NULL\n");
		   return;
   }

   if(munmap (kdbus_transport->kdbus_mmap_ptr, kdbus_transport->receive_pool_size) == -1)
     _dbus_verbose ("munmap when disconnecting failed: %d, %m", errno);
   kdbus_transport->kdbus_mmap_ptr = NULL;
}

/**
 *  Copy-paste from socket transport. Renamed socket_transport to
 *  kdbus_transport and added dbus_connection_set_is_authenticated, because
 *  we do not perform authentication in kdbus, so we have mark is as already done
 *  to make everything work.
 */
static dbus_bool_t
kdbus_connection_set (DBusTransport *transport)
{
  DBusTransportKdbus *kdbus_transport = (DBusTransportKdbus*) transport;

  dbus_connection_set_is_authenticated(transport->connection); //now we don't have authentication in kdbus, so mark it done

  _dbus_watch_set_handler (kdbus_transport->write_watch,
                           _dbus_connection_handle_watch,
                           transport->connection, NULL);

  _dbus_watch_set_handler (kdbus_transport->read_watch,
                           _dbus_connection_handle_watch,
                           transport->connection, NULL);

  if (!_dbus_connection_add_watch_unlocked (transport->connection,
                                            kdbus_transport->write_watch))
    return FALSE;

  if (!_dbus_connection_add_watch_unlocked (transport->connection,
                                            kdbus_transport->read_watch))
    {
      _dbus_connection_remove_watch_unlocked (transport->connection,
                                              kdbus_transport->write_watch);
      return FALSE;
    }

  check_read_watch (transport);
  check_write_watch (transport);

  return TRUE;
}

/**
 *  Copy-paste from socket_transport.
 *  Socket_transport renamed to kdbus_transport
 *
 *   Original dbus copy-pasted @todo comment below.
 * @todo We need to have a way to wake up the select sleep if
 * a new iteration request comes in with a flag (read/write) that
 * we're not currently serving. Otherwise a call that just reads
 * could block a write call forever (if there are no incoming
 * messages).
 */
static  void
kdbus_do_iteration (DBusTransport *transport,
                   unsigned int   flags,
                   int            timeout_milliseconds)
{
  DBusTransportKdbus *kdbus_transport = (DBusTransportKdbus*) transport;
  DBusPollFD poll_fd;
  int poll_res;
  int poll_timeout;

  _dbus_verbose (" iteration flags = %s%s timeout = %d read_watch = %p write_watch = %p fd = %d\n",
                 flags & DBUS_ITERATION_DO_READING ? "read" : "",
                 flags & DBUS_ITERATION_DO_WRITING ? "write" : "",
                 timeout_milliseconds,
                 kdbus_transport->read_watch,
                 kdbus_transport->write_watch,
                 kdbus_transport->fd);

   poll_fd.fd = kdbus_transport->fd;
   poll_fd.events = 0;

   /*
    * TODO test this.
    * This fix is for reply_with_error function.
    * When timeout is set to -1 in client application,
    * error messages are inserted directly to incoming queue and
    * application hangs on dbus_poll.
    */
   if(dbus_connection_get_n_incoming(transport->connection) > 0)
   {
     timeout_milliseconds = 0;
   }
   /* This is kind of a hack; if we have stuff to write, then try
    * to avoid the poll. This is probably about a 5% speedup on an
    * echo client/server.
    *
    * If both reading and writing were requested, we want to avoid this
    * since it could have funky effects:
    *   - both ends spinning waiting for the other one to read
    *     data so they can finish writing
    *   - prioritizing all writing ahead of reading
    */
   if ((flags & DBUS_ITERATION_DO_WRITING) &&
       !(flags & (DBUS_ITERATION_DO_READING | DBUS_ITERATION_BLOCK)) &&
       !transport->disconnected &&
       _dbus_connection_has_messages_to_send_unlocked (transport->connection))
     {
       do_writing (transport);

       if (transport->disconnected ||
           !_dbus_connection_has_messages_to_send_unlocked (transport->connection))
         goto out;
     }

   /* If we get here, we decided to do the poll() after all */
   _dbus_assert (kdbus_transport->read_watch);
   if (flags & DBUS_ITERATION_DO_READING)
     poll_fd.events |= _DBUS_POLLIN;

   _dbus_assert (kdbus_transport->write_watch);
   if (flags & DBUS_ITERATION_DO_WRITING)
     poll_fd.events |= _DBUS_POLLOUT;

   if (poll_fd.events)
   {
      if ( (flags & DBUS_ITERATION_BLOCK) && !(flags & DBUS_ITERATION_DO_WRITING))
        poll_timeout = timeout_milliseconds;
      else
        poll_timeout = 0;

      /* For blocking selects we drop the connection lock here
       * to avoid blocking out connection access during a potentially
       * indefinite blocking call. The io path is still protected
       * by the io_path_cond condvar, so we won't reenter this.
       */
      if (flags & DBUS_ITERATION_BLOCK)
      {
         _dbus_verbose ("unlock pre poll\n");
         _dbus_connection_unlock (transport->connection);
      }

    again:
      poll_res = _dbus_poll (&poll_fd, 1, poll_timeout);

      if (poll_res < 0 && _dbus_get_is_errno_eintr ())
        goto again;

      if (flags & DBUS_ITERATION_BLOCK)
      {
         _dbus_verbose ("lock post poll\n");
         _dbus_connection_lock (transport->connection);
      }

      if (poll_res >= 0)
      {
         if (poll_res == 0)
            poll_fd.revents = 0; /* some concern that posix does not guarantee this;
                                  * valgrind flags it as an error. though it probably
                                  * is guaranteed on linux at least.
                                  */

         if (poll_fd.revents & _DBUS_POLLERR)
            do_io_error (transport);
         else
         {
            dbus_bool_t need_read = (poll_fd.revents & _DBUS_POLLIN) > 0;

            _dbus_verbose ("in iteration, need_read=%d\n",
                             need_read);

            if (need_read && (flags & DBUS_ITERATION_DO_READING))
               do_reading (transport);
            /* We always be able to write to kdbus */
            if (flags & DBUS_ITERATION_DO_WRITING)
               do_writing (transport);
         }
      }
      else
         _dbus_verbose ("Error from _dbus_poll(): %s\n", _dbus_strerror_from_errno ());
   }

 out:
  /* We need to install the write watch only if we did not
   * successfully write everything. Note we need to be careful that we
   * don't call check_write_watch *before* do_writing, since it's
   * inefficient to add the write watch, and we can avoid it most of
   * the time since we can write immediately.
   *
   * However, we MUST always call check_write_watch(); DBusConnection code
   * relies on the fact that running an iteration will notice that
   * messages are pending.
   */
   check_write_watch (transport);

   _dbus_verbose (" ... leaving do_iteration()\n");
}

/**
 * Copy-paste from socket transport.
 */
static void
kdbus_live_messages_changed (DBusTransport *transport)
{
  /* See if we should look for incoming messages again */
  check_read_watch (transport);
}

/**
 * Gets file descriptor of the kdbus bus.
 * @param transport transport
 * @param fd_p place to write fd to
 * @returns always TRUE
 */
static dbus_bool_t
kdbus_get_kdbus_fd (DBusTransport *transport,
                      int           *fd_p)
{
  DBusTransportKdbus *kdbus_transport = (DBusTransportKdbus*) transport;

  *fd_p = kdbus_transport->fd;

  return TRUE;
}

static const DBusTransportVTable kdbus_vtable = {
  transport_finalize,
  kdbus_handle_watch,
  kdbus_disconnect,
  kdbus_connection_set,
  kdbus_do_iteration,
  kdbus_live_messages_changed,
  kdbus_get_kdbus_fd
};

/**
 * Copy-paste from dbus_transport_socket with needed changes.
 *
 * Creates a new transport for the given kdbus file descriptor and address.
 * The file descriptor must be nonblocking.
 *
 * @param fd the file descriptor.
 * @param address the transport's address
 * @returns the new transport, or #NULL if no memory.
 */
static DBusTransport*
new_kdbus_transport (int               fd,
                     const DBusString *address,
                     const char       *activator)
{
  DBusTransportKdbus *kdbus_transport;
#if defined(POLICY_IN_LIB) && !defined(REMOVE_POLICY_FROM_DAEMON)
  char *address_copy;
  PBusConfigParser *config = NULL;
#endif

  kdbus_transport = dbus_new0 (DBusTransportKdbus, 1);
  if (kdbus_transport == NULL)
    return NULL;

  kdbus_transport->write_watch = _dbus_watch_new (fd,
                                                 DBUS_WATCH_WRITABLE,
                                                 FALSE,
                                                 NULL, NULL, NULL);
  if (kdbus_transport->write_watch == NULL)
    goto failed_2;

  kdbus_transport->read_watch = _dbus_watch_new (fd,
                                                DBUS_WATCH_READABLE,
                                                FALSE,
                                                NULL, NULL, NULL);
  if (kdbus_transport->read_watch == NULL)
    goto failed_3;

  if (!_dbus_transport_init_base (&kdbus_transport->base,
                                  &kdbus_vtable,
                                  NULL, address))
    goto failed_4;

  kdbus_transport->fd = fd;

  /* These values should probably be tunable or something. */
  kdbus_transport->max_bytes_read_per_iteration = MAX_BYTES_PER_ITERATION;
  kdbus_transport->max_bytes_written_per_iteration = MAX_BYTES_PER_ITERATION;

  kdbus_transport->kdbus_mmap_ptr = NULL;

  if(activator!=NULL)
    {
      int size = strlen(activator);
      if(size)
        {
          kdbus_transport->activator = dbus_new(char, size + 1 );
          if(kdbus_transport->activator != NULL)
            strcpy(kdbus_transport->activator, activator);
          else
            goto failed_2;
        }
    }
  else
    kdbus_transport->activator = NULL;

  kdbus_transport->matchmaker = matchmaker_new();

  kdbus_transport->daemon_unique_name = NULL;
  kdbus_transport->client_serial = 1;
  kdbus_transport->my_kdbus_id = 0;

#if defined(POLICY_IN_LIB) && !defined(REMOVE_POLICY_FROM_DAEMON)
  kdbus_transport->policy = NULL;
  if (!_dbus_string_copy_data (address, &address_copy))
    {
      goto failed_4;
    }

  if (strstr(address_copy, "system"))
    {
      config = dbus_config_init(SYSTEM_BUS);
      kdbus_transport->policy = dbus_policy_init(config);
      _dbus_verbose("Policy - system\n");
    }
  // "uid-kdbus-system" is for system bus, "uid-kdbus" is session bus
  // "uid-kdbus-pid" is for 'other' buses
  // XXX WTF?
  else if (strstr(address_copy, "kdbus-"))
    {
      _dbus_verbose("No policy used, bus name was uid-kdbus-pid\n");
    }
  else
    {
      config = dbus_config_init(SESSION_BUS);
      kdbus_transport->policy = dbus_policy_init(config);
      _dbus_verbose("Policy - session\n");
    }

  dbus_free(address_copy);
  dbus_config_free(config);

  if(kdbus_transport->policy == NULL)
    {
      _dbus_verbose("Error initializing policies. Check policies configuration\n");
      goto failed_4;
    }
#endif

  return (DBusTransport*) kdbus_transport;

 failed_4:
  _dbus_watch_invalidate (kdbus_transport->read_watch);
  _dbus_watch_unref (kdbus_transport->read_watch);
 failed_3:
  _dbus_watch_invalidate (kdbus_transport->write_watch);
  _dbus_watch_unref (kdbus_transport->write_watch);
 failed_2:
  dbus_free (kdbus_transport);
  return NULL;
}

/**
 * Opens a connection to the kdbus bus
 *
 * @param path the path to kdbus bus
 * @param error return location for error code
 * @returns connection file descriptor or -1 on error
 */
static int
_dbus_connect_kdbus (const char *path,
                     DBusError  *error)
{
  int fd;

  _DBUS_ASSERT_ERROR_IS_CLEAR (error);
  _dbus_verbose ("connecting to kdbus bus %s\n", path);

  fd = open(path, O_RDWR|O_CLOEXEC|O_NONBLOCK);
  if (fd < 0)
    dbus_set_error(error, _dbus_error_from_errno (errno), "Failed to open file descriptor: %s", _dbus_strerror (errno));

  return fd;
}

/**
 * Connects to kdbus, creates and sets-up transport.
 *
 * @param path the path to the bus.
 * @param error address where an error can be returned.
 * @returns a new transport, or #NULL on failure.
 */
static DBusTransport*
_dbus_transport_new_for_kdbus (const char *path,
                               const char *activator,
                               DBusError  *error)
{
  int fd;
  DBusTransport *transport;
  DBusString address;

  _DBUS_ASSERT_ERROR_IS_CLEAR (error);

  if (!_dbus_string_init (&address))
    {
      dbus_set_error (error, DBUS_ERROR_NO_MEMORY, NULL);
      return NULL;
    }

  fd = -1;

  if ((!_dbus_string_append (&address, "kernel:path=")) || (!_dbus_string_append (&address, path)))
    {
      dbus_set_error (error, DBUS_ERROR_NO_MEMORY, NULL);
      goto failed_0;
    }

  fd = _dbus_connect_kdbus (path, error);
  if (fd < 0)
    {
      _DBUS_ASSERT_ERROR_IS_SET (error);
      goto failed_0;
    }

  _dbus_verbose ("Successfully connected to kdbus bus %s\n", path);

  transport = new_kdbus_transport (fd, &address, activator);
  if (transport == NULL)
    {
      dbus_set_error (error, DBUS_ERROR_NO_MEMORY, NULL);
      goto failed_1;
    }

  _dbus_string_free (&address);

  return transport;

  failed_1:
  again:
  if (close (fd) < 0)
    {
      if (errno == EINTR)
        goto again;
    }
  failed_0:
  _dbus_string_free (&address);
  return NULL;
}


/**
 * Opens kdbus transport if method from address entry is kdbus
 *
 * @param entry the address entry to open
 * @param transport_p return location for the opened transport
 * @param error place to store error
 * @returns result of the attempt as a DBusTransportOpenResult enum
 */
DBusTransportOpenResult
_dbus_transport_open_kdbus(DBusAddressEntry  *entry,
                                                   DBusTransport    **transport_p,
                                                   DBusError         *error)
{
  const char *method;

  method = dbus_address_entry_get_method (entry);
  _dbus_assert (method != NULL);

  if (strcmp (method, "kernel") == 0)
    {
      const char *path = dbus_address_entry_get_value (entry, "path");
      const char *activator = dbus_address_entry_get_value (entry, "activator");

      if (path == NULL)
        {
          _dbus_set_bad_address (error, "kernel", "path", NULL);
          return DBUS_TRANSPORT_OPEN_BAD_ADDRESS;
        }

      *transport_p = _dbus_transport_new_for_kdbus (path, activator, error);

      if (*transport_p == NULL)
        {
          _DBUS_ASSERT_ERROR_IS_SET (error);
          return DBUS_TRANSPORT_OPEN_DID_NOT_CONNECT;
        }
      else
        {
          _DBUS_ASSERT_ERROR_IS_CLEAR (error);
          return DBUS_TRANSPORT_OPEN_OK;
        }
    }
  else
    {
      _DBUS_ASSERT_ERROR_IS_CLEAR (error);
      return DBUS_TRANSPORT_OPEN_NOT_HANDLED;
    }
}

DBusWatch*
dbus_transport_get_read_watch(DBusTransport *transport)
{
  return ((DBusTransportKdbus*)transport)->read_watch;
}

char*
dbus_transport_get_activator_name(DBusTransport *transport)
{
  return ((DBusTransportKdbus*)transport)->activator;
}

/** @} */
