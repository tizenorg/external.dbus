#include <dbus/dbus.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef DEBUG_ON
#define DEBUG(...)     printf( __VA_ARGS__)
#else
#define DEBUG(...)
#endif

//#define DEBUG(mod,info)     ( printf("*** [%s(%d): %s]:\t%s\n", __FILE__, __LINE__, mod, info) )

#define BUS_NAME "samsung.test.broadcast"
#define BUS_PATH "/samsung/test/broadcast"
#define BUS_INTERFACE "samsung.test.broadcast"
#define SIGNAL_NAME "TestTest"

struct TestData
{
    char *type;
    char *sender;
    char *interface;
    char *path;
    char *member;
    char *arg0;
    char *arg1;
    char *arg2;
    char *arg3;
};

/**
 * Duplicates a string. Result must be freed with
 * dbus_free(). Returns #NULL if memory allocation fails.
 * If the string to be duplicated is #NULL, returns #NULL.
 *
 * @param str string to duplicate.
 * @returns newly-allocated copy.
 */
char*
_dbus_strdup (const char *str)
{
  size_t len;
  char *copy;

  if (str == NULL)
    return NULL;

  len = strlen (str);

  copy = malloc (len + 1);
  if (copy == NULL)
    return NULL;

  memcpy (copy, str, len + 1);

  return copy;
}

// this function was in signals.c only for testing
// it's rewritten because we cant access DBusString API
// TODO type should be message_type like in DBus rule?
char*
match_rule_to_string (struct TestData *data)
{
  char str[256];

  char *ptr;
  ptr = str;

  if (data->type != NULL)
    {
        ptr = stpcpy(ptr, "type=\'");
        ptr = stpcpy(ptr, data->type);
        ptr = stpcpy(ptr, "\'");
    }

     if (data->interface != NULL)
    {
        if (strlen(str) > 0)
        {
          ptr = stpcpy(ptr, ",");
        }

        ptr = stpcpy(ptr, "interface=\'");
        ptr = stpcpy(ptr, data->interface);
        ptr = stpcpy(ptr, "\'");
    }

     if (data->member != NULL)
    {
        if (strlen(str) > 0)
        {
          ptr = stpcpy(ptr, ",");
        }

        ptr = stpcpy(ptr, "member=\'");
        ptr = stpcpy(ptr, data->member);
        ptr = stpcpy(ptr, "\'");
    }

     if (data->path != NULL)
    {
        if (strlen(str) > 0)
        {
          ptr = stpcpy(ptr, ",");
        }

        ptr = stpcpy(ptr, "path=\'");
        ptr = stpcpy(ptr, data->path);
        ptr = stpcpy(ptr, "\'");
    }

// NOT YET IMPLEMENTED
//   if (data->path_namespace != NULL)
//     {
//       if (_dbus_string_get_length (&str) > 0)
//         {
//           if (!_dbus_string_append (&str, ","))
//             goto nomem;
//         }
//
//       if (!_dbus_string_append_printf (&str, "path_namespace='%s'", data->path))
//         goto nomem;
//     }

     if (data->sender != NULL)
    {
        if (strlen(str) > 0)
        {
          ptr = stpcpy(ptr, ",");
        }

        ptr = stpcpy(ptr, "sender=\'");
        ptr = stpcpy(ptr, data->sender);
        ptr = stpcpy(ptr, "\'");
    }

// NOT YET IMPLEMENTED
//   if (data->destination != NULL)
//     {
//       if (_dbus_string_get_length (&str) > 0)
//         {
//           if (!_dbus_string_append (&str, ","))
//             goto nomem;
//         }
//
//       if (!_dbus_string_append_printf (&str, "destination='%s'", data->destination))
//         goto nomem;
//     }

  // APPEND ARGs
  // TODO add more arguments in a loop


     if (data->arg0 != NULL)
    {
        if (strlen(str) > 0)
        {
          ptr = stpcpy(ptr, ",");
        }

        ptr = stpcpy(ptr, "arg0=\'");
        ptr = stpcpy(ptr, data->arg0);
        ptr = stpcpy(ptr, "\'");
    }

     if (data->arg1 != NULL)
    {
        if (strlen(str) > 0)
        {
          ptr = stpcpy(ptr, ",");
        }

        ptr = stpcpy(ptr, "arg1=\'");
        ptr = stpcpy(ptr, data->arg1);
        ptr = stpcpy(ptr, "\'");
    }

     if (data->arg2 != NULL)
    {
        if (strlen(str) > 0)
        {
          ptr = stpcpy(ptr, ",");
        }

        ptr = stpcpy(ptr, "arg2=\'");
        ptr = stpcpy(ptr, data->arg2);
        ptr = stpcpy(ptr, "\'");
    }

    *ptr = 0;
    ptr = str;

    return _dbus_strdup (ptr);
}

// Signals
int send_signal(struct TestData data)
{
    DBusMessage *msg;
    DBusMessageIter args;
    DBusConnection *conn;
    DBusError err;
    dbus_uint32_t serial = 0; // TODO remove? can send simply NULL


    // initialize the error value
    dbus_error_init(&err);

    // connect to the DBUS session bus, and check for errors;
     DEBUG("[send] Connecting to the DBUS session bus... \n");
    fflush(stdout);

    conn = dbus_bus_get(DBUS_BUS_SESSION, &err);
    if (dbus_error_is_set(&err))
    {
        fprintf(stderr, "error (%s)\n", err.message);
        dbus_error_free(&err);
        return -1;
    }

     DEBUG("[send] Creating a signal... \n");
    fflush(stdout);

    msg = dbus_message_new (DBUS_MESSAGE_TYPE_SIGNAL);
    if (NULL == msg)
    {
        fprintf(stderr, "Message Null\n");
        return -1;
    }

    if(data.interface != NULL)
        dbus_message_set_interface(msg, data.interface);

    if(data.path != NULL)
        dbus_message_set_path(msg, data.path);

    if(data.member != NULL)
        dbus_message_set_member(msg, data.member);

     DEBUG("[send] Appending arguments onto signal... \n");
    fflush(stdout);

    if(data.arg0 != NULL)
    {
        dbus_message_iter_init_append(msg, &args);
        if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &data.arg0))
        {
            fprintf(stderr, "Out Of Memory!\n");
            return -1;
        }
    }

     DEBUG("[send] Sending signal... \n");
    fflush(stdout);

    if (!dbus_connection_send(conn, msg, &serial))
    {
        fprintf(stderr, "Failed. Out Of Memory!\n");
        return -1;
    }
    dbus_connection_flush(conn);

    // free the message and close the connection
    dbus_message_unref(msg);
    dbus_connection_unref(conn);

    return 0;
}

// TODO convert struct into rule string
int add_match(DBusConnection * conn, DBusError *err, struct TestData data)
{
    // add a rule for which messages we want to see
     DEBUG("Adding bus match rule ... \n");
    fflush(stdout);
    char * rule_string = NULL;

    rule_string = match_rule_to_string(&data);
     DEBUG("data to string result: \n\t%s\n", rule_string);

    dbus_bus_add_match(conn, rule_string, err);
    dbus_connection_flush(conn);

    if (dbus_error_is_set(err))
    {
        fprintf(stderr, "Match Error (%s)\n", err->message);
        return -1;
    }

    if(rule_string)
        free(rule_string);

    return 0;
}

int check_parameter(const char *a, const char *b)
{
    if(a != NULL)
    {
        if(strcmp(a,b) != 0)
        {
            printf("[recv] Error, we requested interface %s, but received %s!\n", a, b);
            return -1;
        }

         DEBUG("[recv] parameter ok - %s = %s\n", a, b);
    }
    return 0;
}
/*
 * Check if received message was correctly send to us.
 * so if interface matches, member matches etc..
 *
 */
int check_msg(DBusMessage *msg, struct TestData data)
{
    int ret = -1;
    const char * type = NULL;
    const char *interface = NULL;
    const char *member = NULL;
    const char *path = NULL;
    const char *sender = NULL;
    const char *arg0 = NULL;
    DBusMessageIter args;

    type = dbus_message_type_to_string(dbus_message_get_type(msg));
    interface = dbus_message_get_interface(msg);
    member = dbus_message_get_member(msg);
    sender = dbus_message_get_sender(msg);
    path = dbus_message_get_path(msg);

    if (!dbus_message_iter_init(msg, &args))
    {
//         fprintf(stderr, "Message Has No Parameters\n");
    } else if (DBUS_TYPE_STRING != dbus_message_iter_get_arg_type(&args))
    {
//         fprintf(stderr, "Argument is not string!\n");
    } else
        dbus_message_iter_get_basic(&args, &arg0);

     DEBUG("received: type %s, \n\tinterface %s, \n\tmember %s, \n\tsender %s, \n\tpath %s, \n\targ0 %s\n", type, interface, member, sender, path, arg0);

    if(strcmp(member,"NameAcquired") == 0 || strcmp(member,"NameOwnerChanged") == 0)
    {
        ret = 1; // skip this signals
        goto out;
    }

    if(check_parameter(data.type, type) < 0)
    {
        ret = -1;
        goto out;
    }

    if(check_parameter(data.interface, interface) < 0)
    {
        ret = -1;
        goto out;
    }

   if(check_parameter(data.member, member) < 0)
    {
        ret = -1;
        goto out;
    }

    if(check_parameter(data.path, path) < 0)
    {
        ret = -1;
        goto out;
    }

    if(check_parameter(data.sender, sender) < 0)
    {
        ret = -1;
        goto out;
    }

    ret = 0; // OK

out:
    dbus_message_unref(msg);
    return ret;
}

int receive_signal(struct TestData data)
{
    DBusMessage *msg;
    DBusConnection *conn;
    DBusError err;
    int ret;

    int timeout = 3;

    // initialize the errors
    dbus_error_init(&err);

     DEBUG("[recv] Connecting to the DBUS session bus... \n");
    fflush(stdout);

    conn = dbus_bus_get(DBUS_BUS_SESSION, &err);
    if (dbus_error_is_set(&err))
    {
        fprintf(stderr, "error (%s)\n", err.message);
        dbus_error_free(&err);
        return -1;
    }

    add_match(conn, &err, data);

    // loop listening for signals being emitted
    while (true)
    {

        // non blocking read of the next available message
        dbus_connection_read_write(conn, 0);
        msg = dbus_connection_pop_message(conn);

        // loop again if we haven't read a message
        if (NULL == msg)
        {
            sleep(1);
            if(timeout--)
                continue;
            else
            {
                printf("[recv] No signals received. Timeout.\n");
                return -1;
            }
        }

        ret = check_msg(msg, data);
        if(ret == 1)
            continue;

        return ret;
    }
    // close the connection
    dbus_connection_close(conn);

    return 0;
}

// Other functions
void printHelp()
{
    fprintf (stderr, "Usage: \n serverClient-broadcast send/recv $type $sender $interface $path $member $arg0 $arg1 $arg2\n\n "
        "Parameters can be set to NULL to skip them in add_match\n");
}

char* is_null(char * argument)
{
    if(strcmp(argument,"NULL")==0)
        return NULL;
    else
        return argument;
}

// TODO make it more generic

int main(int argc, char **argv)
{
    char cmd = 0; // 0 -- send
                    // 1 -- recv
                    //-1 -- help
    int ret = 0;
    struct TestData data;

    if (10 > argc)
    {
        printf ("Wrong command argument count. \n");
        printHelp();
        return 1;
    }

    if (0 == strcmp(argv[1], "send") )     cmd = 0;
    else if (0 == strcmp(argv[1], "recv") )     cmd = 1;
    else if (0 == strcmp(argv[1], "--help") )   cmd = -1;


    data.type = is_null(argv[2]);
    data.sender  = is_null(argv[3]);
    data.interface = is_null(argv[4]);
    data.path = is_null(argv[5]);
    data.member = is_null(argv[6]);
    data.arg0 = is_null(argv[7]);
    data.arg1 = is_null(argv[8]);
    data.arg2 = is_null(argv[9]);

    switch(cmd)
    {
        case 0:
            ret = send_signal(data);
            break;
        case 1:
            ret = receive_signal(data);
            break;
        case -1:
            printHelp();
            break;
        default:
            printf ("Unknown command.\n");
            break;
    }

    return ret;
}
