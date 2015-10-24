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

// TODO make it more generic - to array
struct TestData
{
  char *rule1;
  char *rule2;
};

static int
parse_match_key(const char *rule, const char *key, char **pValue)
{
  const char  *pBegin;
  const char  *pValueEnd;
  int         value_length = 0;

  pBegin = strstr(rule, key);
  if(pBegin)
    {
      pBegin += strlen(key);
      pValueEnd = strchr(pBegin, '\'');
      if(pValueEnd)
        {
          value_length = pValueEnd - pBegin;
          *pValue = strndup(pBegin, value_length);
        }
    }
  return value_length;
}

// Signals
int send_signal(struct TestData data)
{
    DBusMessage *msg;
    DBusMessageIter args;
    DBusConnection *conn;
    DBusError err;
    dbus_uint32_t serial = 0; // TODO remove? can send simply NULL
    char * value = NULL;

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

    if(parse_match_key(data.rule1, "interface='", &value))
        dbus_message_set_interface(msg, value);

    if(parse_match_key(data.rule1, "path='", &value))
        dbus_message_set_path(msg, value);

    if(parse_match_key(data.rule1, "member='", &value))
        dbus_message_set_member(msg, value);

     DEBUG("[send] Appending arguments onto signal... \n");
    fflush(stdout);

    // TODO
    if(parse_match_key(data.rule1, "arg0='", &value))
    {
        dbus_message_iter_init_append(msg, &args);
        if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &value))
        {
            fprintf(stderr, "Out Of Memory!\n");
            goto failed;
        }
    }

     DEBUG("[send] Sending signal... \n");
    fflush(stdout);

    if (!dbus_connection_send(conn, msg, &serial))
    {
        fprintf(stderr, "Failed. Out Of Memory!\n");
        goto failed;
    }
    dbus_connection_flush(conn);

    // free the message and close the connection
    dbus_message_unref(msg);
    dbus_connection_unref(conn);

    if(value)
      free(value);
    return 0;

  failed:
    if(value)
      free(value);
    return -1;
}

// TODO convert struct into rule string
int add_match(DBusConnection * conn, DBusError *err, struct TestData data)
{
    printf("add_match() rule1: %s\n", data.rule1);
    dbus_bus_add_match(conn, data.rule1, err);

    if(data.rule2 != NULL)
    {
      printf("add_match() rule2: %s\n", data.rule2);
      dbus_bus_add_match(conn, data.rule2, err);
    }

    dbus_connection_flush(conn);

    if (dbus_error_is_set(err))
    {
        fprintf(stderr, "Match Error (%s)\n", err->message);
        return -1;
    }

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
int check_msg(DBusMessage *msg, struct TestData data, DBusConnection *conn)
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
         fprintf(stderr, "Message Has No Parameters\n");
    } else if (DBUS_TYPE_STRING != dbus_message_iter_get_arg_type(&args))
    {
         fprintf(stderr, "Argument is not string!\n");
    } else
        dbus_message_iter_get_basic(&args, &arg0);

     printf("received: type %s, \n\tinterface %s, \n\tmember %s, \n\tsender %s, \n\tpath %s, \n\targ0 %s\n", type, interface, member, sender, path, arg0);

    if(strcmp(member,"NameAcquired") == 0 || strcmp(member,"NameOwnerChanged") == 0)
    {
        ret = 1; // skip this signals
        printf("skipping msg\n");
        goto out;
    }

    // NO CHECKING IF SIGNAL MATCHES - TODO (now rules are in form of string that needs to be parsed)

    ret = 0;

out:
    dbus_message_unref(msg);
    return ret;
}

int remove_match(DBusConnection *conn, struct TestData data)
{
  DBusError err;

  // initialize the errors
  dbus_error_init(&err);
  printf("remove_match() rule 2: %s\n", data.rule2);

  if(data.rule2 != NULL)
    dbus_bus_remove_match(conn, data.rule2, &err);

  if (dbus_error_is_set(&err))
  {
      fprintf(stderr, "RemoveMatch Error (%s)\n", err.message);
      dbus_error_free(&err);
      return -1;
  }

  return 0;
}

int receive_signal(struct TestData data)
{
    DBusMessage *msg;
    DBusConnection *conn;
    DBusError err;
    int ret;
    dbus_bool_t expect_no_signal = FALSE;

    int timeout;

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
loop:
    timeout = 3;
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
                if(expect_no_signal) // timeout expected
                {
                  printf("[recv] Second signal not received. Good\n");
                  return 0;
                }

                printf("[recv] Eror - No signals received. Timeout.\n");
                return -1;
            }
        }
        ret = check_msg(msg, data, conn); // see if signal is correct
        if(ret == 1) // NameOwnerChanged or NameAcquired - skip this message
            continue;

        if(ret == 0) // first signal received ok, now remove match and see if second signal comes
        {
          printf("[recv] First signal received ok!\n");

          if(remove_match(conn, data) < 0)
          {
            return -1;
          }

          expect_no_signal = TRUE; // loop again and wait for second signal
          goto loop;
        }
        return ret;
    }
    // close the connection
    dbus_connection_unref(conn);
    dbus_connection_close(conn);

    return 0;
}

// Other functions
void printHelp()
{
    fprintf (stderr, "Usage: \n serverClient-broadcast-remove-match send/recv \"rule1\" [\"rule2\"]\n\n "
        "You need to provide at least one rule for add_match/remove_match\n");
}

// TODO make it more generic
// TODO remove magic numbers
// TODO refactor connecting to bus - its copied now

int main(int argc, char **argv)
{
    char cmd = 0; // 0 -- send
                    // 1 -- recv
                    //-1 -- help
    int ret = 0;
    struct TestData data;

    if (3 > argc)
    {
        printf ("Wrong command argument count. \n");
        printHelp();
        return 1;
    }

    if (0 == strcmp(argv[1], "send") )     cmd = 0;
    else if (0 == strcmp(argv[1], "recv") )     cmd = 1;
    else if (0 == strcmp(argv[1], "--help") )   cmd = -1;

    data.rule1 = argv[2]; // at least one rule has to be

    if (argc == 4)
      data.rule2 = argv[3];

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
