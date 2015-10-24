/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/* kdbus-d.h  kdbus related daemon functions
 *
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

#ifndef KDBUS_D_H_
#define KDBUS_D_H_


#include <dbus/dbus-bus.h>
#include "bus.h"
#include "signals.h"
#include <dbus/dbus-server.h>
#include <linux/types.h>
#include <dbus/dbus-transport-kdbus.h>
#include <dbus/kdbus-common.h>

char*           make_kdbus_bus              (DBusBusType type, const char* address, DBusError *error);
DBusServer*     empty_server_init           (char* address);

dbus_bool_t     kdbus_register_policy       (const DBusString *service_name, DBusConnection* connection);
dbus_bool_t     kdbus_list_services         (DBusTransport* transport, char ***listp, int *array_len);
dbus_bool_t     kdbus_list_queued           (DBusTransport *transport, DBusList **return_list, const char *name,
                                             DBusError *error);
void            matchRule_set_cookie        (DBusConnection *connection, BusMatchRule *rule);
dbus_bool_t     kdbus_add_match_rule        (DBusConnection *connection, const char *sender, BusMatchRule *rule,
                                             DBusError *error);

int             kdbus_get_name_owner        (DBusTransport* transport, const char* name, char* owner);
dbus_bool_t     kdbus_get_connection_unix_selinux_security_context(DBusTransport* transport, DBusMessage* message, DBusMessage* reply, DBusError* error);

DBusConnection* daemon_as_client            (char* address, DBusError *error);
dbus_bool_t     register_daemon_name        (DBusConnection* connection);
void            enable_activator_watch      (BusConnections *connections, const char *name);
dbus_bool_t     register_kdbus_starters     (DBusConnection* connection);
dbus_bool_t     update_kdbus_starters       (DBusConnection* connection);
int             drop_message                (DBusConnection *connection);

void            handleNameOwnerChanged      (DBusMessage *msg, BusTransaction *transaction, DBusConnection *connection);
#endif /* KDBUS_H_ */
