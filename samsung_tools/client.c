#include <stdio.h>

#include <dbus/dbus.h>

#include <string.h>
#include <sys/time.h>
#include <stdlib.h>
#include <getopt.h>

#define DEFAULT_DBUS_NAME "com.samsung.pingpong"
#define DEFAULT_DBUS_PATH "/com/samsung/pingpong"
#define DEFAULT_DBUS_IFACE "com.samsung.pingpong"

char *dbus_name = DEFAULT_DBUS_NAME;
char *dbus_path = DEFAULT_DBUS_PATH;
char *dbus_iface = DEFAULT_DBUS_IFACE;

enum MessageType {
  MSG_TYPE_NONE,
  MSG_TYPE_PING,
  MSG_TYPE_RELEASENAME
};

DBusConnection *dbus_conn;
struct timeval tv_start, tv_end;
int message_serial;
enum MessageType message_type = MSG_TYPE_PING;
long int iter_count = 5;

void
shutdown_dbus ()
{
  if (dbus_conn)
    {
      dbus_connection_close (dbus_conn);
    }
}

unsigned int
send_ping_message(DBusConnection *dbus_conn)
{
  DBusMessage *message;
  unsigned int message_serial;
  static char* arg_str = "Ping";

  message = dbus_message_new_method_call (dbus_name, dbus_path, dbus_iface, "Ping");
  if(message == NULL)
    {
      fprintf (stderr,"Error - unable to create message.\n");
      return -1;
    }

  if(dbus_message_append_args (message, DBUS_TYPE_STRING,
                               &arg_str, DBUS_TYPE_INVALID)  != TRUE)
    {
      fprintf (stderr,"Error - unable to append arguments.\n");
      return -1;
    }

  if(dbus_connection_send (dbus_conn, message, &message_serial) != TRUE)
    {
      fprintf (stderr,"Error - dbus_connection_send fails due to lack of memory.\n");
      return -1;
    }
  printf("Sending Ping message (serial:%d). ", message_serial);
  dbus_message_unref (message);
  return message_serial;
}

unsigned int
send_releasename_message(DBusConnection *dbus_conn)
{
  DBusMessage *message;
  unsigned int message_serial;
  static char* arg_str = "ReleaseName";

  message = dbus_message_new_method_call (dbus_name, dbus_path, dbus_iface, "ReleaseName");
  if(message == NULL)
    {
      fprintf (stderr,"Error - unable to create message.\n");
      return -1;
    }

  if(dbus_message_append_args (message, DBUS_TYPE_STRING,
                               &arg_str, DBUS_TYPE_INVALID)  != TRUE)
    {
      fprintf (stderr,"Error - unable to append arguments.\n");
      return -1;
    }

  if(dbus_connection_send (dbus_conn, message, &message_serial) != TRUE)
    {
      fprintf (stderr,"Error - dbus_connection_send fails due to lack of memory.\n");
      return -1;
    }

  printf("Sending ReleaseName message (serial:%d).\n", message_serial);
  dbus_message_unref (message);
  return message_serial;
}

DBusHandlerResult
handler(DBusConnection *conn, DBusMessage *msg, void *user_data)
{
  //char buffer[1024];
  DBusError error;
  const char *dbus_data;

  if (dbus_message_get_reply_serial (msg) != message_serial)
    {
      return DBUS_HANDLER_RESULT_HANDLED;
    }

  dbus_error_init (&error);

  if(dbus_message_get_type (msg) == DBUS_MESSAGE_TYPE_ERROR)
    {
      fprintf(stderr, "Error - Invalid ping message!\n");
      if(!dbus_message_get_args (msg,&error,DBUS_TYPE_STRING,&dbus_data,DBUS_TYPE_INVALID))
        {
          fprintf (stderr,"error: %s\n",error.message);
          shutdown_dbus ();
          exit(1);
        }
      printf("Error msg: %s\n", dbus_data);
      shutdown_dbus ();
      exit(1);
    }

  if(!dbus_message_get_args (msg,&error,DBUS_TYPE_STRING,&dbus_data,DBUS_TYPE_INVALID))
    {
      fprintf (stderr,"error: %s\n",error.message);
      shutdown_dbus ();
      exit(1);
    }
  else
    {
      static long int iter = 0;
      static long int avg = 0;
      static long int sum = 0;
      long int delta = 0;

      gettimeofday (&tv_end, NULL);
      delta = (1000000*tv_end.tv_sec + tv_end.tv_usec) - (1000000*tv_start.tv_sec + tv_start.tv_usec);
      printf("Reply received after %ld us\n", delta);
      sum += delta;
      iter++;
      if(iter == iter_count)
        {
          avg = sum / iter_count;
          printf ("avg RTT: %ld us\n", avg);
          shutdown_dbus ();
          exit(0);
        }
      message_serial = send_ping_message(dbus_conn);
      if(message_serial < 0)
        {
          fprintf(stderr, "Error - unable to send message!\n");
          shutdown_dbus ();
          exit(1);
        }
      gettimeofday (&tv_start, NULL);
    }
  return DBUS_HANDLER_RESULT_HANDLED;
}

int
init_dbus ()
{
  DBusError error;
  dbus_error_init (&error);

  dbus_conn = dbus_bus_get_private(DBUS_BUS_SESSION, &error);

  if (dbus_error_is_set (&error))
    {
      fprintf (stderr, "Couldn't initialize DBus: %s\n", error.message);
      return -1;
    }

  printf("Connected to bus\n");
  return 0;
}

int
main (int argc, char **argv)
{
  int c;
  static struct option long_options[] =
    {
      {"help",  no_argument,        NULL, 'h'},
      {"type",  required_argument,  NULL, 't'},
      {"name",  required_argument,  NULL, 'n'},
      {"count", required_argument,  NULL, 'c'},
      {0, 0, 0, 0}
    };

  int option_index = 0;
  while ((c = getopt_long (argc, argv, "ht:n:c:", long_options, &option_index)) != -1 )
    {
      switch (c)
      {
        case 'h':
          printf ("Help:\n");
          printf ("Usage: ./ping-client [OPTS]\n\n");
          printf ("Options:\n");
          printf ("\t-t, --type\t\tMessege type (Ping or ReleaseName)\n");
          printf ("\t-c, --count\t\tserver will terminate after given message count\n");
          printf ("\t-n, --name\t\tset dbus name (used also for path and interface)\n");
          printf ("\t-h, --help\t\tshow this help message and exit\n");
          return 0;
          break;

        case 't':
          if(optarg != NULL)
            {
              if(!strcmp(optarg, "Ping"))
                {
                  message_type = MSG_TYPE_PING;
                  printf("Client mode: Ping.\n");
                }
              else
              if(!strcmp(optarg, "ReleaseName"))
                {
                  message_type = MSG_TYPE_RELEASENAME;
                  printf("Client mode: ReleaseName.\n");
                }
              else
                {
                  fprintf(stderr, "Unknown message type.\n");
                  return 1;
                }
            }
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
          iter_count = atoi(optarg);
          if(iter_count <= 0)
            {
              fprintf(stderr, "Unsupported value of 'c' argument.\n");
              return 1;
            }
          else
            printf("Iteration count: %ld\n", iter_count);
          break;

        default:
          break;
      }
    }

  printf("dbus_name: \"%s\"\n", dbus_name);
  printf("dbus_path: \"%s\"\n", dbus_path);
  printf("dbus_iface: \"%s\"\n", dbus_iface);

  if (init_dbus () < 0)
    {
      fprintf (stderr, "Cannot initialize DBus\n");
      return 1;
    }

  dbus_connection_add_filter (dbus_conn, handler, NULL, NULL);

  switch(message_type)
  {
    case MSG_TYPE_PING:
      message_serial = send_ping_message(dbus_conn);
      if(message_serial < 0)
        {
          fprintf(stderr, "Error - unable to send message!\n");
          shutdown_dbus ();
          return 1;
        }
      gettimeofday (&tv_start, NULL);
      break;

    case MSG_TYPE_RELEASENAME:
      message_serial = send_releasename_message(dbus_conn);
      if(message_serial < 0)
        {
          fprintf(stderr, "Error - unable to send message!\n");
          shutdown_dbus ();
          return 1;
        }
      return 0;
      break;

    default:
      fprintf(stderr, "Unknown message type.\n");
      return 1;
      break;
  }

  while (dbus_connection_read_write (dbus_conn, -1))
    {
      while (dbus_connection_dispatch (dbus_conn) != DBUS_DISPATCH_COMPLETE) {};
    }
  //free(ping);

  return 0;
}
