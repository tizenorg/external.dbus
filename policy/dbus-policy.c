/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/* dbus-policy.c - helper library for fine-grained userspace policy handling
 *
 * Copyright (C) 2014 Samsung Electronics
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
 * Author: Lukasz Skalski <l.skalski@samsung.com>
 *
 */

#include <config.h>
#include <stdio.h>

#include "../bus/policy.h"
#include "../bus/config-parser.h"
#include "dbus-policy.h"
#include <stdlib.h>

static char* init_conf_file_path()
{
  const char *s = _dbus_getenv (CUSTOM_BUS_CONF_FILE_ENV);
  return s && *s ? strdup(s) : NULL;
}

/*
 * dbus_policy_check_can_send():
 *
 */
int dbus_policy_check_can_send (PBusClientPolicy *client_policy,
                                int          message_type,
                                const char  *destination,
                                const char  *path,
                                const char  *interface,
                                const char  *member,
                                const char  *error_name,
                                int          reply_serial,
                                int          requested_reply)
{
  dbus_bool_t requested_reply_bool = FALSE;

  if (requested_reply)
    requested_reply_bool = TRUE;

  if (!bus_policy_check_can_send (client_policy,
                                  requested_reply_bool,
                                  message_type,
                                  destination,
                                  path,
                                  interface,
                                  member,
                                  error_name,
                                  reply_serial))
    return 0;
  else
    return 1;
}


/*
 * dbus_policy_check_can_recv():
 *
 */
int dbus_policy_check_can_recv (PBusClientPolicy *client_policy,
                                int          message_type,
                                const char  *sender,
                                const char  *path,
                                const char  *interface,
                                const char  *member,
                                const char  *error_name,
                                int          reply_serial,
                                int          requested_reply)
{
  dbus_bool_t requested_reply_bool = FALSE;

  if (requested_reply)
    requested_reply_bool = TRUE;

  if (!bus_policy_check_can_receive (client_policy,
                                     requested_reply_bool,
                                     message_type,
                                     sender,
                                     path,
                                     interface,
                                     member,
                                     error_name,
                                     reply_serial))
    return 0;
  else
    return 1;
}


/*
 * dbus_policy_check_can_own():
 *
 */
int dbus_policy_check_can_own (PBusClientPolicy *client_policy,
                               const char *service_name)
{
  DBusString dbus_service_name;
  _dbus_string_init_const (&dbus_service_name, service_name);

  if(!bus_client_policy_check_can_own (client_policy,
                                        &dbus_service_name))
    return 0;
  else
    return 1;
}


/*
 * dbus_policy_print_rules():
 *
 */
void dbus_policy_print_rules (PBusClientPolicy *client_policy)
{
  bus_client_policy_print (client_policy);
}


/*
 * dbus_config_init():
 *
 */
PBusConfigParser* dbus_config_init (unsigned int bus_type)
{
  DBusString config_file;
  char * custom_bus_conf_file_path;
  dbus_bool_t r;
  void* ret = NULL;
  DBusError error;

  if (!_dbus_string_init (&config_file))
    return NULL;

  custom_bus_conf_file_path = init_conf_file_path();

  if(custom_bus_conf_file_path != NULL)
  {
    r = _dbus_string_append (&config_file, custom_bus_conf_file_path);
    _dbus_verbose("Using custom configuration file: %s\n", custom_bus_conf_file_path);
  }
  else if (bus_type == SYSTEM_BUS)
    r = _dbus_string_append (&config_file, SYSTEM_BUS_CONF_FILE);
  else if (bus_type == SESSION_BUS)
    r = _dbus_string_append (&config_file, SESSION_BUS_CONF_FILE);
  else
    goto out;

  if (r == FALSE)
    goto out;

  /*
   * BusConfigParser
   */
  dbus_error_init (&error);
  ret = bus_config_load (&config_file, TRUE, NULL, &error);
  dbus_error_free(&error);

out:
  free(custom_bus_conf_file_path);
  _dbus_string_free(&config_file);
  return ret;

}

/*
 * dbus_config_free():
 *
 */
void dbus_config_free (PBusConfigParser *config)
{
  if (config != NULL)
    bus_config_parser_unref (config);
}

int dbus_config_check_message_size(PBusConfigParser *config, long size)
{
  BusLimits limits;
  if (config == NULL)
    return -1;
  bus_config_parser_get_limits(config, &limits);
  return (size <= limits.max_message_size) ? 1 : 0;
}

/*
 * dbus_policy_init():
 *
 */
PBusClientPolicy* dbus_policy_init (PBusConfigParser *config)
{
  BusPolicy       *policy;
  PBusClientPolicy *client_policy = NULL;
  DBusError error;

  if (config == NULL)
    return NULL;

  /*
   * BusPolicy
   */
  policy = bus_config_parser_steal_policy (config);
  if (policy == NULL)
    return NULL;
  /*
   * BusClientPolicy
   */
  dbus_error_init (&error);
  client_policy = bus_policy_create_client_policy (policy, NULL, &error);
  dbus_error_free(&error);

  /*
   * Free unused memory
   */
  bus_policy_unref (policy);

  return client_policy;
}


/*
 * dbus_policy_free():
 *
 */
void dbus_policy_free (PBusClientPolicy *client)
{
  if (client != NULL)
    bus_client_policy_unref (client);
}
