//gcc -o server server.c -Wall -g -O0 `pkg-config --cflags --libs dbus-1`

#include <dbus/dbus.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>

#define DEFAULT_DBUS_NAME "com.samsung.pingpong"
#define DEFAULT_DBUS_PATH "/com/samsung/pingpong"
#define DEFAULT_DBUS_IFACE "com.samsung.pingpong"

char *dbus_name = DEFAULT_DBUS_NAME;
char *dbus_path = DEFAULT_DBUS_PATH;
char *dbus_iface = DEFAULT_DBUS_IFACE;

DBusConnection *dbus_conn;
DBusObjectPathVTable *dbus_vtable;
int repeat_count = -1;

void
shutdown_dbus ()
{
  if (dbus_conn)
    {
      dbus_connection_close(dbus_conn);
      free(dbus_vtable);
    }
}

static DBusHandlerResult
handler_function(DBusConnection *conn, DBusMessage *msg, void *user_data)
{
  DBusMessage *reply;

  DBusError error;
  dbus_error_init(&error);

  char * ping = NULL;

  if(dbus_message_get_type (msg) == DBUS_MESSAGE_TYPE_ERROR)
    {
      fprintf(stderr, "Error - Invalid ping message!\n");
      return -1;
    }

  if (!dbus_message_get_args ( msg,
                               &error,
                               DBUS_TYPE_STRING,
                               &ping,
                               DBUS_TYPE_INVALID))
    {
      fprintf(stderr, "Error - Invalid ping message! Arguments missing.\n");
      reply = dbus_message_new_error(msg, "com.pingpong.PingError","ping message arguments missing");
      dbus_connection_send(dbus_conn, reply, NULL);
      return -1;
    }

  if(dbus_message_is_method_call(msg, dbus_iface, "Ping"))
    {
      printf ("Received Ping message (serial:%d). ", dbus_message_get_serial(msg));
      reply = dbus_message_new_method_return(msg);
      if(reply == NULL)
        {
          fprintf (stderr,"Error - unable to create message.\n");
          return -1;
        }

      if(dbus_message_append_args (reply, DBUS_TYPE_STRING,
                                   &ping, DBUS_TYPE_INVALID)  != TRUE)
        {
          fprintf (stderr,"Error - unable to append arguments.\n");
          return -1;
        }

      if(dbus_connection_send (dbus_conn, reply, NULL) != TRUE)
        {
          fprintf (stderr,"Error - dbus_connection_send fails due to lack of memory.\n");
          return -1;
        }
      printf("Sending reply message.\n");
      dbus_message_unref(reply);
    }
  else
  if(dbus_message_is_method_call(msg, dbus_iface, "ReleaseName"))
    {
      printf ("Received ReleaseName from client. Releasing %s!\n", dbus_name);
      dbus_bus_release_name(conn, dbus_name, &error);
      shutdown_dbus();
      if(dbus_error_is_set(&error))
        {
          fprintf(stderr,"Release name failed!\n");
          exit(1);
        }
      exit(0);
    }
  else
    printf ("Received unknown method call.");

  if(repeat_count > 0 )
    {
      repeat_count--;
      printf("--- %d messages left.\n", repeat_count);
      if(!repeat_count)
        {
          shutdown_dbus();
          exit(0);
        }
    }
  return DBUS_HANDLER_RESULT_HANDLED;
}

int
init_dbus()
{
  DBusError error;
  int flag;
  dbus_error_init(&error);

  dbus_conn = dbus_bus_get_private(DBUS_BUS_SESSION,&error);
  if(dbus_error_is_set(&error))
    {
      fprintf(stderr,"Error- could not initizalize dbus session: %s \n", error.message);
      return -1;
    }

  printf("Connected to bus\n");

  switch(flag = dbus_bus_request_name(dbus_conn, dbus_name, 0, &error))
  {
    case DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER:
    case DBUS_REQUEST_NAME_REPLY_IN_QUEUE:
      //printf("server.c request_name flags %d\n",flag);
      //printf("server.c Name registered as %s\n",dbus_name);
      break;
    default:
      fprintf(stderr,"Error - could not request name. Flag: %d\n", flag);
      fprintf(stderr,"error message %s. \n", error.message);
      return -1;
  }

  printf("Request name: success\n");

  dbus_vtable = malloc(sizeof(DBusObjectPathVTable));
  dbus_vtable->unregister_function = NULL;

  dbus_vtable->message_function = handler_function;

  if(!dbus_connection_register_object_path(dbus_conn,
                                           dbus_path,
                                           dbus_vtable,
                                           NULL))
    {
      fprintf(stderr,"Error - could not register object path");
      return -1;
    }

  return 0;
}


int
main(int argc, char **argv)
{
  int c;
  static struct option long_options[] =
    {
      {"infinite",  no_argument,        NULL, 'i'},
      {"help",      no_argument,        NULL, 'h'},
      {"name",      required_argument,  NULL, 'n'},
      {"count",     required_argument,  NULL, 'c'},
      {0, 0, 0, 0}
    };

  int option_index = 0;

  while ((c = getopt_long (argc, argv, "ihn:c:", long_options, &option_index)) != -1 )
    {
      switch (c)
      {
        case 'i':
          printf("Server mode: infinite message read.\n");
          break;

        case 'n':
          {
            int size;
            char *tmp;

            if(!dbus_validate_bus_name(optarg, NULL))
              {
                printf("dbus_validate_bus_name \"%s\" failed.\n", optarg);
                return 1;
              }

            size = strlen(optarg);
            dbus_name  = alloca(size+1);
            dbus_iface = dbus_name;
            dbus_path  = alloca(size+2); // additional '/' in the string beginning

            strcpy(dbus_name,  optarg);
            strcpy(dbus_iface, optarg);
            dbus_path[0] = '/';   // first sign must be '/'
            strcpy(dbus_path+1, optarg);

            tmp = dbus_path+1;
            while(*tmp != '\0')   // replace '.' with '/'
              {
                if(*tmp == '.')
                  *tmp = '/';
                tmp++;
              }
          }
          break;

        case 'c':
          repeat_count = atoi(optarg);
          if(repeat_count <= 0)
            {
              printf("Unsupported value of 'c' argument.\n");
              return 1;
            }
          else
            printf("Server mode: terminate after %d message read.\n", repeat_count);
          break;

        case 'h':
          printf ("Help:\n");
          printf ("Usage: ./ping-server [OPTS]\n\n");
          printf ("Options:\n");
          printf ("\t-i, --infinite\t\tserver works constantly\n");
          printf ("\t-c, --count\t\tserver will terminate after given message count\n");
          printf ("\t-n, --name\t\tset dbus name (used also for path and interface)\n");
          printf ("\t-h, --help\t\tshow this help message and exit\n");
          return 0;
          break;

        default:
          break;
      }
    }

  printf("dbus_name: \"%s\"\n", dbus_name);
  printf("dbus_path: \"%s\"\n", dbus_path);
  printf("dbus_iface: \"%s\"\n", dbus_iface);

  if (init_dbus() < 0)
    {
      fprintf(stderr, "%s: Error initializing dbus\n", __FILE__);
      return 1;
    }

  printf("Waiting for clients...\n");

  while (dbus_connection_read_write(dbus_conn, -1))
    {
      while (dbus_connection_dispatch( dbus_conn) != DBUS_DISPATCH_COMPLETE) {};
    }

  shutdown_dbus();
  return 0;
}
