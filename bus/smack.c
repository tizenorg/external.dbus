/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/* smack.c - Provide interface to query smack context
 *
 * Author: Brian McGillion <brian.mcgillion@intel.com>
 * Copyright © 2012 Intel Corporation
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#include <config.h>
#include "smack.h"

#include <dbus/dbus-internals.h>

#include "connection.h"
#include "services.h"
#include "utils.h"
#include "policy.h"

#include <stdlib.h>
#include <stdio.h>

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef DBUS_ENABLE_SMACK
#include <sys/smack.h>
#endif

#define SMACK_WRITE "W"
#define SMACK_READ "R"
#define SMACK_READ_WRITE "RW"
#define SMACK_MAX_LABEL_LENGTH 24

int
have_smack(void)
{
#ifdef DBUS_ENABLE_SMACK
  static int have = -1;

  if (have == -1)
    {
      if(smack_smackfs_path() == NULL)
        have = 0;
      else
        have = 1;
    }
  return have;
#else
  return 0;
#endif
}

char *
bus_smack_get_label (DBusConnection *connection, DBusError *error)
{
#ifdef DBUS_ENABLE_SMACK
  char *label;
  int sock_fd;

  if (!have_smack())
    return NULL;
  if (!dbus_connection_get_socket(connection, &sock_fd))
    {
      dbus_set_error (error, DBUS_ERROR_FAILED,
                      "Failed to get the socket descriptor of the connection.\n");
      _dbus_verbose ("Failed to get socket descriptor of connection for Smack check.\n");
      return NULL;
    }
  /* retrieve an ascii, null-terminated string that defines the Smack context of the connected socket */
  if (smack_new_label_from_socket(sock_fd, &label) < 0)
    {
      dbus_set_error (error, DBUS_ERROR_FAILED,
                      "Failed to read the Smack context from the connection socket: %s.\n",
                      _dbus_strerror (errno));
      _dbus_verbose ("Failed to read the Smack context from the connection socket: %s.\n",
                     _dbus_strerror (errno));
      return NULL;
    }
  return label;
#else
  return NULL;
#endif
}

void
bus_smack_label_free (char *label)
{
  if (label)
    free (label);
}

dbus_bool_t
bus_smack_handle_get_connection_context (DBusConnection *connection,
                                         BusTransaction *transaction,
                                         DBusMessage    *message,
                                         DBusError      *error)
{
#ifdef DBUS_ENABLE_SMACK
  const char *remote_end = NULL;
  BusRegistry *registry;
  DBusString remote_end_str;
  BusService *service;
  DBusConnection *remote_connection;
  DBusMessage *reply = NULL;
  char *label = NULL;

  _DBUS_ASSERT_ERROR_IS_CLEAR (error);

  registry = bus_connection_get_registry (connection);

  if (!dbus_message_get_args (message, error, DBUS_TYPE_STRING, &remote_end,
                              DBUS_TYPE_INVALID))
    return FALSE;

  _dbus_verbose ("asked for label of connection %s\n", remote_end);

  _dbus_string_init_const (&remote_end_str, remote_end);

  service = bus_registry_lookup (registry, &remote_end_str);
  if (service == NULL)
    {
      dbus_set_error (error, DBUS_ERROR_NAME_HAS_NO_OWNER,
                      "Bus name '%s' has no owner", remote_end);
      return FALSE;
    }

  remote_connection = bus_service_get_primary_owners_connection (service);
  if (remote_connection == NULL)
    goto oom;

  reply = dbus_message_new_method_return (message);
  if (reply == NULL)
    goto oom;

  label = bus_smack_get_label (remote_connection, error);
  if (label == NULL)
    {
      dbus_set_error (error, DBUS_ERROR_FAILED,
                      "Failed to get the socket fd of the connection",
                      remote_end);
      goto err;
    }

  if (!dbus_message_append_args (reply, DBUS_TYPE_STRING,
                                 &label, DBUS_TYPE_INVALID))
    goto oom;

  if (!bus_transaction_send_from_driver (transaction, connection, reply))
    goto oom;

  dbus_message_unref (reply);
  dbus_free(label);

  return TRUE;

oom:
  BUS_SET_OOM (error);

err:
  if (reply != NULL)
    dbus_message_unref (reply);

  dbus_free(label);

  return FALSE;
#else
  dbus_set_error (error, DBUS_ERROR_NOT_SUPPORTED,
                  "SMACK support is not enabled");
  return FALSE;
#endif
}

#ifdef DBUS_ENABLE_SMACK
static int
bus_smack_has_access (const char *subject, const char *object,
                      const char *access)
{

  if (!have_smack())
    return TRUE;
  return smack_have_access (subject, object, access);
}
#endif

/**
 * Calculate the list of rules that apply to a connection.
 *
 * @param connection The inbound conenction
 * @param rules_by_smack_label The table of object labels -> rules mapping
 * @param allowed_list the list of permitted rules if it exists, otherwise NULL.
 * @returns TRUE on success, False otherwise.
 */
dbus_bool_t
bus_smack_generate_allowed_list (DBusConnection *connection,
                                 DBusHashTable  *rules_by_smack_label,
                                 dbus_pid_t pid,
                                 DBusList **allowed_list)
{
#ifdef DBUS_ENABLE_SMACK
  const char *subject_label = NULL;
  DBusHashIter iter;
  int is_allowed;
  DBusList *rule_list = NULL;

  if (connection == NULL)    /* only for libdbuspolicy purposes */
    {
      FILE *file;
      char *label_file_name;
      char subject_label_from_file [SMACK_MAX_LABEL_LENGTH];

      if (asprintf(&label_file_name, "/proc/%d/attr/current", pid) < 0)
        return FALSE;

      file = fopen (label_file_name, "r");
      if(file == NULL)
        {
          _dbus_verbose ("[SMACK] Can't open %s\n", label_file_name);
          return FALSE;
        }
      free (label_file_name);

      fgets(subject_label_from_file,SMACK_MAX_LABEL_LENGTH,file);
      _dbus_verbose ("[SMACK] Subject label: %s\n", subject_label_from_file);
      subject_label = subject_label_from_file;

      fclose(file);
    }
  else
    {
      /* the label of the subject, is the label on the new connection,
         either the service itself or one of its clients */
      subject_label = bus_connection_get_smack_label (connection);
    }
  if(!have_smack())
    subject_label = _dbus_strdup("NO_SMACK");

  if (subject_label == NULL)
    return FALSE;

  /* Iterate over all the smack labels we have parsed from the .conf files */
  _dbus_hash_iter_init (rules_by_smack_label, &iter);
  while (_dbus_hash_iter_next (&iter))
    {
      DBusList *link;
      const char *object_label = _dbus_hash_iter_get_string_key (&iter);
      /* the list here is all the rules that are 'protected'
         by the SMACK label named $object_label */
      DBusList **list = _dbus_hash_iter_get_value (&iter);

      for (link = _dbus_list_get_first_link (list);
           link != NULL;
           link = _dbus_list_get_next_link (list, link))
        {
          BusPolicyRule *rule = link->data;
          is_allowed = 0;

          switch (rule->type)
            {
            case BUS_POLICY_RULE_OWN:
              is_allowed = bus_smack_has_access (subject_label,
                                                 object_label,
                                                 "RWX");
              break;

            case BUS_POLICY_RULE_SEND:
              is_allowed = bus_smack_has_access (subject_label,
                                                 object_label,
                                                 "W");
              break;

            case BUS_POLICY_RULE_RECEIVE:
              is_allowed = bus_smack_has_access (subject_label,
                                                 object_label,
                                                 "R");
              break;

            default:
              continue;
            }

          if ((is_allowed) || (is_allowed == -1)) /* access allowed or access isn't possible to check */
            {
              if (!_dbus_list_append (&rule_list, rule))
                goto nomem;

              bus_policy_rule_ref (rule);
            }

          _dbus_verbose ("permission request subject (%s) -> object (%s) : %d\n", subject_label, object_label, is_allowed);
        }
    }

  *allowed_list = rule_list;

  if(subject_label
     && !have_smack())
    dbus_free (subject_label);

  return TRUE;

 nomem:
  if (rule_list != NULL)
    {
      _dbus_list_clear (&rule_list);
      dbus_free (rule_list);
    }
  return FALSE;
#else
  return TRUE;
#endif
}
