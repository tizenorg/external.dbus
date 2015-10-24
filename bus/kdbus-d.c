/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/* kdbus-d.c  kdbus related daemon functions
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
#include <dbus/dbus-connection-internal.h>
#include "kdbus-d.h"
#include <linux/kdbus.h>
#include <dbus/dbus-bus.h>
#include "dispatch.h"
#include <dbus/dbus-transport.h>
#include <dbus/dbus-transport-kdbus.h>
#include "connection.h"
#include "activation.h"
#include "services.h"
#include <dbus/dbus-connection.h>
#include "signals.h"
#include "dbus/dbus-signals.h"

#include <utils.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include <dbus/dbus-watch.h>

#ifdef SMACK_LABELED_BUS
#include <sys/smack.h>

/**
 * Waits for file smack label to be change from "_" to something else
 * @param file_name Name of file
 * @param timeout Time for waiting (units: 10ms)
 * @returns 0 if label changed, 1 on error (eg. timeout < 0)
 *          or if label not changed
 */
int wait_for_smack_label_change(char *file_name, int timeout)
{
  int ret;
  char *label;

  if (timeout < 0)
    return 1;

  while(timeout--)
    {
	  label = NULL;
      ret = smack_getlabel(file_name, &label, SMACK_LABEL_ACCESS);
      if (ret == 0)
        {
          _dbus_verbose("Bus smack label: %s\n", label);
          if (strcmp("_", label) != 0)
            {
              free(label);
              _dbus_verbose("Label set\n");
              return 0;
            }
		    if(label != NULL)
			free(label);
        }
      usleep(10*1000);
    }
  _dbus_verbose("Smack label for bus file was not set\n");
  return 1;
}
#endif

/*
 * Creates kdbus bus of given type.
 */
char*
make_kdbus_bus(DBusBusType  type,
               const char  *address,
               DBusError   *error)
{
  // TODO Function alloca() used. In upstream there was a patch proposing to
  // replace alloca() with malloc() to assure memory alignment. If there will be
  // suggestion to use malloc instead of alloca this function has to be modified
  struct kdbus_cmd_make *bus_make;
  struct kdbus_item     *item;
  __u64 name_size, bus_make_size;
  int  fdc = 0;
  int  ret;
  char *bus = NULL;
  char *name = NULL;

  if(type == DBUS_BUS_SYSTEM)
    name_size = asprintf(&name, "%u-%s", getuid(), "system") + 1;
  else if(type == DBUS_BUS_SESSION)
    name_size = asprintf(&name, "%u-%s", getuid(), "user") + 1;
  else
retry_default:
    name_size = asprintf(&name, "%u-%u", getuid(), getpid()) + 1;

  if (name_size < 0)
    return NULL;

  bus_make_size = sizeof(struct kdbus_cmd_make) + KDBUS_ITEM_SIZE(name_size) + KDBUS_ITEM_SIZE(sizeof(struct kdbus_bloom_parameter));
  bus_make = alloca(bus_make_size);
  if (!bus_make)
    {
      free(name);
      return NULL;
    }

  bus_make->size = bus_make_size;
  bus_make->flags = KDBUS_MAKE_ACCESS_WORLD;

  item = bus_make->items;
  item->type = KDBUS_ITEM_MAKE_NAME;
  item->size = KDBUS_ITEM_HEADER_SIZE + name_size;
  memcpy((bus_make->items)->str, name, name_size);
  free(name);

  item = KDBUS_ITEM_NEXT(item);
  item->type = KDBUS_ITEM_BLOOM_PARAMETER;
  item->size = KDBUS_ITEM_HEADER_SIZE + sizeof(struct kdbus_bloom_parameter);
  item->bloom_parameter.size = 64;
  item->bloom_parameter.n_hash = 1;

  if(fdc == 0)
    {
#ifdef SMACK_LABELED_BUS
      _dbus_verbose("Waiting for smack label change on /dev/kdbus/control\n");
      //wait for setting smack label for control file and silently ignore fail
      wait_for_smack_label_change("/dev/kdbus/control", 1000);
#endif
      _dbus_verbose("Opening /dev/kdbus/control\n");
      fdc = open("/dev/kdbus/control", O_RDWR|O_CLOEXEC);
    }
  if (fdc < 0)
    {
      _dbus_verbose("--- error %d (%m)\n", fdc);
      dbus_set_error(error, DBUS_ERROR_FAILED, "Opening /dev/kdbus/control failed: %d (%m)", fdc);
      return NULL;
    }

  _dbus_verbose("Creating bus '%s'\n", (bus_make->items[0]).str);
  ret = ioctl(fdc, KDBUS_CMD_BUS_MAKE, bus_make);
  if (ret && errno != EEXIST)
    {
      static dbus_bool_t retry = TRUE;
      _dbus_verbose("--- error %d (%m)\n", errno);
      dbus_set_error(error, DBUS_ERROR_FAILED, "Creating bus '%s' failed: %d (%m)",
          (bus_make->items[0]).str, errno);

      if(retry == TRUE)
        {
          retry = FALSE;
          dbus_error_free(error);
          goto retry_default;
        }
      return NULL;
    }
  else if(ret && errno == EEXIST)
    {
      _dbus_verbose("Bus '%s' already exists.\n", address);
      bus = strdup(address);
      return bus;
    }

#ifdef SMACK_LABELED_BUS
  {
    char *bus_file;
    if (asprintf(&bus_file, "/dev/kdbus/%s/bus", (bus_make->items[0]).str) < 0)
      {
        BUS_SET_OOM (error);
        return NULL;
      }

    //wait for setting smack label for bus file and silently ignore fail
    _dbus_verbose("Waiting for smack label change on %s\n", bus_file);
    wait_for_smack_label_change(bus_file, 500);
    free(bus_file);

  }
#endif

  if (asprintf(&bus, "kernel:path=/dev/kdbus/%s/bus", (bus_make->items[0]).str) < 0)
    {
      BUS_SET_OOM (error);
      return NULL;
    }

  _dbus_verbose("Created bus '%s'\n", bus);
  return bus;
}

/*
 * Minimal server init needed by context to go further.
 */
DBusServer*
empty_server_init(char *address)
{
  return dbus_server_init_mini(address);
}

/**
 * Add matches for ALL messages related to changing/adding/removing names and ids.
 * see add_name_change_match() in libsystemd
 * TODO - instead of copying these matches in Daemon source,
 * we could copy and use add_name_change_match() from libsystemd
 */
static dbus_bool_t
add_matches_for_kdbus_broadcasts(DBusConnection *connection)
{
  struct kdbus_cmd_match  *m;
  struct kdbus_item       *item;
  uint64_t size;
  int fd;
  DBusTransport *transport;

  transport = dbus_connection_get_transport(connection);

  if(!_dbus_transport_get_socket_fd(transport, &fd))
    {
      errno = EPERM;
      return FALSE;
    }

  size = KDBUS_ALIGN8(offsetof(struct kdbus_cmd_match, items) +
      offsetof(struct kdbus_item, name_change) +
      offsetof(struct kdbus_notify_name_change, name));

  m = alloca(size);
  if(m == NULL)
    {
      errno = ENOMEM;
      return FALSE;
    }

  m->cookie = 1;
  m->size = size;

  /* first match against any name change */
  item = m->items;
  item->size =
      offsetof(struct kdbus_item, name_change) +
      offsetof(struct kdbus_notify_name_change, name);
  item->name_change.old.id = KDBUS_MATCH_ID_ANY;
  item->name_change.new.id = KDBUS_MATCH_ID_ANY;

  item->type = KDBUS_ITEM_NAME_CHANGE;
  if(ioctl(fd, KDBUS_CMD_MATCH_ADD, m))
    {
      _dbus_verbose("Failed adding match rule for name changes for daemon, error: %d, %m\n", errno);
      return FALSE;
    }

  _dbus_verbose("Added match rule for daemon correctly.\n");
  return TRUE;
}

/*
 * Connects daemon to bus created by him and adds matches for "system" broadcasts.
 * Do not requests org.freedesktop.DBus name, because it's to early
 * (some structures of BusContext are not ready yet).
 */
DBusConnection*
daemon_as_client(char      *address,
                 DBusError *error)
{
  DBusConnection *connection;
#ifdef MATCH_IN_LIB
  MatchRule *rule;
  DBusString str;
  Matchmaker *matchmaker;
#endif

  connection = daemon_bus_get(address, error);
  if(connection == NULL)
      return NULL;

  if(!add_matches_for_kdbus_broadcasts(connection))
    {
      dbus_set_error (error, _dbus_error_from_errno (errno), "Could not add match for daemon, %s", _dbus_strerror_from_errno ());
      goto failed;
    }

#ifdef MATCH_IN_LIB
  _dbus_string_init_const (&str, "type='signal',interface='org.freedesktop.DBus',member='NameOwnerChanged'");
  rule = match_rule_parse (connection, &str, error);
  if (rule == NULL)
    goto failed;

  matchmaker = dbus_transport_get_matchmaker(dbus_connection_get_transport(connection));
  if (!matchmaker_add_rule (matchmaker, rule))
      BUS_SET_OOM (error);
#endif

  if(dbus_error_is_set(error))
    {
      failed:
      _dbus_connection_close_possibly_shared (connection);
      dbus_connection_unref (connection);
      connection = NULL;
    }
  else
    _dbus_verbose ("Daemon connected as kdbus client.\n");

  return connection;
}

/*
 * Asks bus for org.freedesktop.DBus well-known name.
 */
dbus_bool_t register_daemon_name(DBusConnection *connection)
{
  DBusString      daemon_name;
  dbus_bool_t     retval = FALSE;
  BusTransaction  *transaction;

  _dbus_string_init_const(&daemon_name, DBUS_SERVICE_DBUS);

  if(request_kdbus_name(dbus_connection_get_transport(connection), DBUS_SERVICE_DBUS, 0) != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER)
    return FALSE;

  transaction = bus_transaction_new (bus_connection_get_context(connection));
  if (transaction == NULL)
    {
      release_kdbus_name(dbus_connection_get_transport(connection), DBUS_SERVICE_DBUS);
      goto out;
    }

  if(!bus_registry_ensure (bus_connection_get_registry (connection), &daemon_name, connection, 0, transaction, NULL))
    {
      release_kdbus_name(dbus_connection_get_transport(connection), DBUS_SERVICE_DBUS);
      goto out;
    }

  retval = TRUE;

  out:
  if(retval)
    bus_transaction_execute_and_free(transaction);
  else
    bus_transaction_cancel_and_free(transaction);

  return retval;
}

/*
 * Asks kdbus for well-known names registered on the bus
 */
dbus_bool_t
kdbus_list_services (DBusTransport *transport,
                     char        ***listp,
                     int           *array_len)
{
  struct kdbus_cmd_name_list  cmd;
  struct kdbus_name_list      *name_list;
  struct kdbus_cmd_name       *name;
  dbus_bool_t ret_val = FALSE;

  int   fd;
  int   i = 0;
  int   list_len = 0;
  char  **list;

  _dbus_transport_get_socket_fd(transport, &fd);

  cmd.flags = KDBUS_NAME_LIST_NAMES | KDBUS_NAME_LIST_UNIQUE;

  again:
  if(ioctl(fd, KDBUS_CMD_NAME_LIST, &cmd))
    {
      if(errno == EINTR)
        goto again;
      else
        {
          _dbus_verbose("kdbus error asking for name list: err %d (%m)\n",errno);
          return FALSE;
        }
    }

  name_list = (struct kdbus_name_list *)((char *)dbus_transport_get_pool_pointer(transport) + cmd.offset);

  KDBUS_ITEM_FOREACH(name, name_list, names)
    {
      list_len++;
      if(name->size > sizeof(struct kdbus_cmd_name) )
        list_len++;
    }


  _dbus_verbose ("List len: %d\n", list_len);

  list = malloc(sizeof(char*) *(list_len + 1)); // TODO use some convenient data structure
  if(list == NULL)
    goto out;

  KDBUS_ITEM_FOREACH(name, name_list, names)
  {
    // for Well-known names - just copy
    if(name->size > sizeof(struct kdbus_cmd_name) )
      {
        list[i] = strdup(name->name);
        if(list[i] == NULL)
          goto out;
        _dbus_verbose ("Name %d: %s\n", i, list[i]);
        ++i;
      }

    // for Unique ids - convert them to string
    if(asprintf(&list[i], ":1.%020llu", (unsigned long long)name->owner_id) < 0)
      goto out;
    _dbus_verbose ("Name %d: %s\n", i, list[i]);
    ++i;
  }

  list[i] = NULL;
  *array_len = list_len;
  *listp = list;
  ret_val = TRUE;

  out:
  if (ioctl(fd, KDBUS_CMD_FREE, &cmd.offset) < 0)
    {
      if(errno == EINTR)
        goto out;

      _dbus_verbose("kdbus error freeing pool: %d (%m)\n", errno);

      ret_val = FALSE;
    }
  if(ret_val == FALSE)
    {
      dbus_free_string_array (list);

      *array_len = 0;
      *listp = NULL;
    }

  return ret_val;
}

/*
 * Asks kdbus for list of connections being in the queue to own
 * given well-known name. The list does NOT include the owner of the name on the
 * first position ANYMORE. Kdbus does not return owner currently
 */
dbus_bool_t
kdbus_list_queued (DBusTransport *transport,
                   DBusList     **return_list,
                   const char    *name,
                   DBusError     *error)
{
  struct kdbus_cmd_name_list    cmd = {};
  struct kdbus_name_list        *name_list;
  struct kdbus_cmd_name         *owner;
  dbus_bool_t                   ret_val = FALSE;
  int fd;

  _dbus_verbose ("Asking for queued owners of %s\n", name);

  _dbus_transport_get_socket_fd(transport, &fd);

  cmd.flags = KDBUS_NAME_LIST_QUEUED;

  again:
  if(ioctl(fd, KDBUS_CMD_NAME_LIST, &cmd))
    {
      if(errno == EINTR)
        goto again;

      else if(errno == ESRCH)
        {
          dbus_set_error (error, DBUS_ERROR_NAME_HAS_NO_OWNER,
              "Could not get owners of name '%s': no such name", name);
          return FALSE;
        }
      else
        {
          _dbus_verbose("kdbus error asking for queued owners list: err %d (%m)\n",errno);
          goto out;
        }
    }


  name_list = (struct kdbus_name_list *)((char *)dbus_transport_get_pool_pointer(transport) + cmd.offset);
  _dbus_verbose ("ioctl ok, name_list size is %llu\n", name_list->size);

  KDBUS_ITEM_FOREACH(owner, name_list, names)
  {
    char *uname = NULL;

    _dbus_verbose ("iteration - queued owner id: %llu\n", (unsigned long long)owner->owner_id);

    if(strcmp((owner->name), name) != 0)
      continue;

    if(asprintf(&uname, ":1.%020llu", (unsigned long long)owner->owner_id) < 0)
      goto out;

    if (!_dbus_list_append (return_list, uname))
      goto out;
  }

  ret_val = TRUE;

  out:
  if (ioctl(fd, KDBUS_CMD_FREE, &cmd.offset) < 0)
    {
      if(errno == EINTR)
        goto out;

      _dbus_verbose("kdbus error freeing pool: %d (%m)\n", errno);
      ret_val = FALSE;
    }

  if(ret_val == FALSE)
    {
      DBusList *link;

      dbus_set_error (error, _dbus_error_from_errno (errno),
          "Failed to list queued owners of \"%s\": %s",
          name, _dbus_strerror (errno));

      link = _dbus_list_get_first_link (return_list);
      while (link != NULL)
        {
          DBusList *next = _dbus_list_get_next_link (return_list, link);

          if(link->data != NULL)
            free(link->data);

          _dbus_list_free_link (link);
          link = next;
        }
    }

  return ret_val;
}

void
matchRule_set_cookie(DBusConnection *connection,
                     BusMatchRule   *rule)
{
  DBusList *rules_list;
  BusMatchRule *last_rule;
  __u64 cookie;

  rules_list = bus_connection_get_match_rules_list(connection);
  last_rule = _dbus_list_get_last(&rules_list);
  if(last_rule)
    cookie = bus_match_rule_get_cookie(last_rule) + 1;
  else
    cookie = 1;
  bus_match_rule_set_cookie(rule, cookie);
}

int
kdbus_get_name_owner(DBusTransport *transport,
                     const char    *name,
                     char          *owner)
{
  int ret;
  struct nameInfo info;

  ret = kdbus_NameQuery(name, transport, &info);
  if(ret == 0) //unique id of the name
    {
      free(info.sec_label);
      if(info.flags & KDBUS_HELLO_ACTIVATOR)
        return -ESRCH;
      sprintf(owner, ":1.%020llu", (unsigned long long int)info.uniqueId);
      _dbus_verbose("Unique name discovered:%s\n", owner);
    }
  else if((ret != -ESRCH) && (ret != -ENXIO))
    _dbus_verbose("kdbus error sending name query: err %d (%m)\n", ret);

  return ret;
}

/*
 *  Asks kdbus for selinux_security_context of the owner of the name given in the message
 */
dbus_bool_t
kdbus_get_connection_unix_selinux_security_context(DBusTransport *transport,
                                                   DBusMessage   *message,
                                                   DBusMessage   *reply,
                                                   DBusError     *error)
{
  char  *name = NULL;
  int   inter_ret;
  dbus_bool_t     ret = FALSE;
  struct nameInfo info;

  dbus_message_get_args(message, NULL, DBUS_TYPE_STRING, &name, DBUS_TYPE_INVALID);
  inter_ret = kdbus_NameQuery(name, transport, &info);
  if((inter_ret == -ESRCH) || (inter_ret == -ENXIO)) //name has no owner
    dbus_set_error (error, DBUS_ERROR_FAILED, "Could not get security context of name '%s': no such name", name);
  else if(inter_ret < 0)
    {
      _dbus_verbose("kdbus error determining security context: err %d (%m)\n", errno);
      dbus_set_error (error, DBUS_ERROR_FAILED, "Could not determine security context for '%s'", name);
    }
  else
    {
      if (!dbus_message_append_args (reply, DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &info.sec_label, info.sec_label_len, DBUS_TYPE_INVALID))
        {
          free(info.sec_label);
          _DBUS_SET_OOM (error);
          return FALSE;
        }
      free(info.sec_label);
      ret = TRUE;
    }

  return ret;
}

static void
kdbus_activate_service (void * data)
{
  DBusConnection  *activator_conn = (DBusConnection  *)data;
  DBusConnection *daemon_conn;
  BusActivation *activation;

  BusTransaction *transaction = NULL;
  BusContext *context;
  DBusError error;
  DBusMessage *msg;
  char *name = dbus_transport_get_activator_name(dbus_connection_get_transport(activator_conn));

  msg = _dbus_connection_pop_message_unlocked(activator_conn);

  dbus_error_init (&error);

  context = bus_connection_get_context (activator_conn);
  daemon_conn = bus_context_get_daemon_connection(context);
  activation = bus_connection_get_activation (activator_conn);
  transaction = bus_transaction_new (context);

  if (!bus_activation_activate_service (activation, daemon_conn,
                  transaction, TRUE, msg, name, &error))
  {
    _dbus_verbose ("bus_activation_activate_service() failed: %s\n", error.name);
    dbus_error_free(&error);
  }

  dbus_message_unref (msg);

  if (transaction != NULL)
    bus_transaction_execute_and_free (transaction);

  //TODO check blocking
  _dbus_connection_toggle_watch_unlocked(activator_conn, dbus_transport_get_read_watch(dbus_connection_get_transport(activator_conn)), FALSE);
}

/**
 * TODO handle errors
 */

int
drop_message(DBusConnection *connection)
{
  int fd;
  struct kdbus_cmd_recv recv = {
            .flags = KDBUS_RECV_DROP
    };

  if(!_dbus_transport_get_socket_fd(dbus_connection_get_transport(connection), &fd))
    return -1;

  if (ioctl(fd, KDBUS_CMD_MSG_RECV, &recv) < 0)
    return -errno;

  return 0;
}

void
enable_activator_watch(BusConnections *connections,
                       const char     *name)
{
  DBusConnection *connection;

  connection = bus_connections_find_activator_by_name(connections, name);
  if(connection == NULL)
    return;

  _dbus_connection_lock(connection);
  _dbus_connection_toggle_watch_unlocked(connection, dbus_transport_get_read_watch(dbus_connection_get_transport(connection)), TRUE);
  _dbus_connection_unlock(connection);
}

static DBusConnection*
create_activator_connection(DBusConnection *connection,
                            const char     *name)
{
  DBusConnection  *activator_conn = NULL;
  DBusError error;
  DBusString bus_name;
  const char *path_str;
  char *path_str_activator;
  BusContext* context;
  const char * const activator_prefix = ",activator=";

  _dbus_verbose ("Creating activator\n");

  dbus_error_init(&error);
  _dbus_string_init_const(&bus_name, name);

  context = bus_connection_get_context(connection);
  path_str = bus_context_get_address(context);

  path_str_activator = (char *)malloc(strlen(path_str) +
                                      strlen(activator_prefix) +
                                      strlen(name) + 1);
  strcpy(path_str_activator, path_str);
  strcat(path_str_activator, activator_prefix);
  strcat(path_str_activator, name);

  activator_conn = daemon_bus_get(path_str_activator, &error);
  if (activator_conn == NULL)
    {
      dbus_error_free(&error);
      return NULL;
    }

  free(path_str_activator);

  //  dbus_bus_set_unique_name(activator_conn, name);

  _dbus_verbose ("Created activator connection for %s\n", name);

  return activator_conn;
}

/*
 * Registers activatable services as kdbus starters.
 */
dbus_bool_t
register_kdbus_starters(DBusConnection *connection)
{
  int   i, len;
  char  **services;
  dbus_bool_t     retval = FALSE;
  DBusConnection * activator_conn;

  if (!bus_activation_list_services (bus_connection_get_activation (connection), &services, &len))
    return FALSE;

  for(i=0; i<len; i++)
    {
      activator_conn = create_activator_connection(connection, services[i]);
      if(activator_conn == NULL)
        goto out;

      if(!bus_connections_add_activator(bus_connection_get_connections(connection), activator_conn, services[i]))
        {
          dbus_connection_unref(activator_conn);
          activator_conn = NULL;
          goto out;
        }

      dbus_connection_set_wakeup_main_function(activator_conn, kdbus_activate_service, activator_conn, NULL);
      _dbus_verbose (" activator name %s added to registry\n", services[i] );
    }
  retval = TRUE;

  out:
  if(retval == FALSE)
    bus_connections_clear_activators(bus_connection_get_connections(connection));

  dbus_free_string_array (services);

  return retval;
}

/*
 * Updates kdbus starters (activatable services) after configuration was reloaded.
 * It releases all previous starters and registers all new.
 */
dbus_bool_t
update_kdbus_starters(DBusConnection *connection)
{
  bus_connections_clear_activators(bus_connection_get_connections(connection));

  if(!register_kdbus_starters(connection))
    {
      _dbus_verbose ("Registering kdbus starters for dbus activatable names failed!\n");
      return FALSE;
    }

  return TRUE;
}

/*
 * Analyzes system broadcasts about id and name changes.
 * Basing on this it sends NameAcquired and NameLost signals.
 */
void
handleNameOwnerChanged(DBusMessage    *msg,
                       BusTransaction *transaction,
                       DBusConnection *connection)
{
  const char *name, *old, *new;

  if(!dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &name, DBUS_TYPE_STRING, &old, DBUS_TYPE_STRING, &new, DBUS_TYPE_INVALID))
    {
      _dbus_verbose ("Couldn't get args of NameOwnerChanged signal.\n");//, error.message);
      return;
    }

  _dbus_verbose ("Got NameOwnerChanged signal:\nName: %s\nOld: %s\nNew: %s\n", name, old, new);

  if((*old == 0) && (*new == 0))
    return;

  if(strncmp(name, ":1.", 3))/*if it doesn't start from :1. it is well-known name*/
    {
      if((*new != 0) && (strcmp(new, bus_connection_get_name(connection))))
        bus_activation_service_created (bus_connection_get_activation (connection),
                name, transaction, NULL);
    }
}
