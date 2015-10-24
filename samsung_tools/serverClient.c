// 18.06.2013 15:00

#include <dbus/dbus.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_SIGNAL_NAME            "Test"
#define TEST_SIGNAL_INTERFACE       "test.signal.Type"
#define TEST_SIGNAL_PATH            "/test/signal/Object"
#define SIGNAL_SERVER_NAME          "test.signal.sink"
#define SIGNAL_SERVER_MATCH_RULE    "type='signal',interface='test.signal.Type'"
#define TEST_METHOD_INTERFACE       "test.method.Type"
#define TEST_METHOD_PATH            "/test/method/Object"
#define TEST_METHOD_NAME            "Method"
#define TEST_METHOD_VALUE           "Sample test string - Radek"
#define METHOD_SERVER_NAME          "test.method.server"
#define METHOD_CLIENT_NAME          "test.method.caller"
#define REPLY_TIMEOUT               15000

#define FLAG_RELEASE_NAME                   (1 << 0)
#define FLAG_RELEASE_MATCH                  (1 << 1)
#define FLAG_ADD_MATCH_ORG_FREEDESKTOP_DBUS (1 << 2)
#define FLAG_GET_BUS_ID                     (1 << 3)
#define FLAG_GET_SELINUX_SECURITY           (1 << 4)
#define FLAG_LIST_NAMES                     (1 << 5)
#define FLAG_GET_SERVER_OWNER               (1 << 6)
#define FLAG_SERVER_HAS_OWNER               (1 << 7)
#define FLAG_GET_SERVER_UNIX_USER           (1 << 8)
#define FLAG_GET_SERVER_PID                 (1 << 9)
#define FLAG_GET_SERVER_CREDS               (1 << 10)
#define FLAG_LIST_ACTIVATABLE               (1 << 11)
#define FLAG_ACTIVATE                       (1 << 12)
#define FLAG_LIST_QUEUED                    (1 << 13)
#define FLAG_DELAY_ANSWER                   (1 << 14)
#define FLAG_UPDATE_ACTIVATION_ENV          (1 << 15)

#define EXIT_CODE_SUCCESS                 0
#define EXIT_CODE_FATAL_ERORR             1
#define EXIT_CODE_VALID_REPLY_ERROR       2
#define EXIT_CODE_WRONG_PROGRAM_ARGUMENTS 3

void printErrorReply(DBusMessage* reply, DBusError* err)
{
	unsigned int repserial;
	unsigned int serial;
	const char* errorName;
	char* perrMsg = NULL;

	repserial = dbus_message_get_reply_serial(reply);
	serial = dbus_message_get_serial(reply);
	errorName = dbus_message_get_error_name(reply);
	dbus_message_get_args(reply, err, DBUS_TYPE_STRING, &perrMsg,	DBUS_TYPE_INVALID);
  if (dbus_error_is_set(err))
    {
      fprintf(stderr, "Reading reply error failed (%s)\n", err->message);
      dbus_error_free(err);
      exit(EXIT_CODE_FATAL_ERORR);
    }

	printf( "Error message!\nSerial: %d\nReplay serial: %d\nError name:%s\nError message: %s\n",
			serial, repserial, errorName, perrMsg);
}

DBusConnection* connectWithName(const char* name, DBusError* err)
{
	DBusConnection* conn;

	// connect to the DBUS system bus, and check for errors
	conn = dbus_bus_get(DBUS_BUS_SESSION, err);
	if (dbus_error_is_set(err))
	  {
	    fprintf(stderr, "Connection Error (%s)\n", err->message);
	    dbus_error_free(err);
	    exit(EXIT_CODE_FATAL_ERORR);
	  }

	printf("My unique name on the bus is: %s\n",	dbus_bus_get_unique_name(conn));
	if (name)
	  {
	    int ret;

	    // register our name on the bus, and check for errors
      ret = dbus_bus_request_name(conn, name, DBUS_NAME_FLAG_ALLOW_REPLACEMENT | DBUS_NAME_FLAG_REPLACE_EXISTING, err);
      if (dbus_error_is_set(err))
        {
          fprintf(stderr, "Name Error (%s)\n", err->message);
          dbus_error_free(err);
          exit(EXIT_CODE_FATAL_ERORR);
        }
      if (DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER != ret)
        {
          if (ret == DBUS_REQUEST_NAME_REPLY_IN_QUEUE)
            printf("Name in queue!\n");
          else if (ret == DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER)
            printf("Already owner!\n");
          else if (ret == DBUS_REQUEST_NAME_REPLY_EXISTS)
            {
              fprintf(stderr, "Already exists!\n");
              exit(EXIT_CODE_FATAL_ERORR);
            }
          else
            {
              fprintf(stderr, "Ret value %d!\n", ret);
              exit(EXIT_CODE_FATAL_ERORR);
            }
        }
      else
        printf("Acquired well known name: %s\n", name);
	}

	return conn;
}

// deregisters name on the bus and check for errors
void releaseName(DBusConnection *conn, const char *name)
{
  int ret;
  DBusError err;

  dbus_error_init(&err);
  ret = dbus_bus_release_name(conn, name, &err);
  if (dbus_error_is_set(&err))
  {
    fprintf(stderr, "Name release error (%s)\n", err.message);
    dbus_error_free(&err);
    exit(EXIT_CODE_FATAL_ERORR);
  }
  if (DBUS_RELEASE_NAME_REPLY_RELEASED != ret)
  {
    if(ret == DBUS_RELEASE_NAME_REPLY_NOT_OWNER)
      {
        fprintf(stderr, "Can not release - DBUS_RELEASE_NAME_REPLY_NOT_OWNER received\n");
        exit(EXIT_CODE_VALID_REPLY_ERROR);
      }
    else
      exit(EXIT_CODE_FATAL_ERORR);
  }
  else
    printf("Name released correctly.\n");
}

char* readStringFromMsg(DBusMessage *msg)
{
  DBusMessageIter args;
  char *string = NULL;

  // read the parameters
  if (!dbus_message_iter_init(msg, &args))
    {
      fprintf(stderr,"Message has no parameters\n");
      exit(EXIT_CODE_FATAL_ERORR);
    }
  else if (DBUS_TYPE_STRING != dbus_message_iter_get_arg_type(&args))
    {
      fprintf(stderr,"Argument is not string!\n");
      exit(EXIT_CODE_FATAL_ERORR);
    }
  else
    dbus_message_iter_get_basic(&args, &string);

  return string;
}

DBusPendingCall* methodDBusNoArgs(DBusConnection *conn, const char* method)
{
	DBusPendingCall *pending;
	DBusMessage *msg;

	msg = dbus_message_new_method_call(DBUS_SERVICE_DBUS, DBUS_PATH_DBUS,
			DBUS_INTERFACE_DBUS, method); // method name
	if (NULL == msg)
	  {
	    fprintf(stderr, "Message Null\n");
	    exit(EXIT_CODE_FATAL_ERORR);
	  }

	// send message and get a handle for a reply
	if (!dbus_connection_send_with_reply(conn, msg, &pending, REPLY_TIMEOUT)) // -1 is default timeout
	  {
	    fprintf(stderr, "Sending with reply failed!\n");
	    exit(EXIT_CODE_FATAL_ERORR);
	  }
	if (NULL == pending)
	  {
	    fprintf(stderr, "Pending Call Null\n");
	    exit(EXIT_CODE_FATAL_ERORR);
	  }
	dbus_connection_flush(conn);

	printf("%s sent...\n", method);
	dbus_message_unref(msg);  // free message

	return pending;
}

DBusPendingCall* methodDBusWArg(DBusConnection *conn, const char* method,
		int type, void* data)
{
	DBusPendingCall *pending;
	DBusMessage *msg;
	DBusMessageIter args;

	msg = dbus_message_new_method_call(DBUS_SERVICE_DBUS, DBUS_PATH_DBUS, DBUS_INTERFACE_DBUS, method); // method name
	if (NULL == msg)
	  {
	    fprintf(stderr, "Message Null\n");
	    exit(EXIT_CODE_FATAL_ERORR);
	  }
	// append arguments
	dbus_message_iter_init_append(msg, &args);
	if (!dbus_message_iter_append_basic(&args, type, data))
	  {
	    fprintf(stderr, "Out Of Memory!\n");
	    exit(EXIT_CODE_FATAL_ERORR);
	  }

	// send message and get a handle for a reply
	if (!dbus_connection_send_with_reply(conn, msg, &pending, REPLY_TIMEOUT)) // -1 is default timeout
	  {
	    fprintf(stderr, "Sending with reply failed!\n");
	    exit(EXIT_CODE_FATAL_ERORR);
	  }
	if (NULL == pending)
	  {
	    fprintf(stderr, "Pending Call Null\n");
	    exit(EXIT_CODE_FATAL_ERORR);
	  }
	dbus_connection_flush(conn);

	printf("%s sent...\n", method);
	dbus_message_unref(msg);  // free message

	return pending;
}

DBusMessage* getMessageNoError(DBusPendingCall *pending)
{
	DBusMessage *msg = NULL;
	DBusMessageIter args;
	DBusError err;

	dbus_error_init(&err);
	msg = dbus_pending_call_steal_reply(pending);  // get the reply message
	if (NULL == msg)
	  {
	    fprintf(stderr, "Reply Null\n");
	    exit(EXIT_CODE_FATAL_ERORR);
	  }
	dbus_pending_call_unref(pending); 	// free the pending message handle
	printf("reply received\n");

	if (dbus_message_get_type(msg) == DBUS_MESSAGE_TYPE_ERROR)
	  {
	    printErrorReply(msg, &err);
	    dbus_message_unref(msg);
	    msg = NULL;
	    exit(EXIT_CODE_VALID_REPLY_ERROR);
	    /* This brakes execution. If errors here are acceptable and can be detected
	     * by parsing printout this exit could be removed, but at every call checking if
	     * message returned is not NULL must be added! */
	  }
	else if (!dbus_message_iter_init(msg, &args))
	  {
	    fprintf(stderr, "Message has no arguments!\n");
	    dbus_message_unref(msg);
	    msg = NULL;
	    exit(EXIT_CODE_FATAL_ERORR);
	  }
	return msg;
}

/* example
key = "LD_LIBRARY_PATH";
value = "/home/r.pajak/workspace/dbus/dbus/.libs"
*/
dbus_bool_t updActEnv(DBusConnection *conn, char* upd_env)
{
	DBusMessage *msg;
	DBusPendingCall *pending;
	DBusMessageIter array_iter;
	DBusMessageIter dict_iter;
	DBusMessageIter dict_entry_iter;
	const char *key = NULL;
	const char *value = NULL;

	key = strtok(upd_env,"=\0");
	printf("Found key: %s\n", key);
	value = strtok(NULL,"=\0");
	printf("Found value: %s\n", value);

	msg = dbus_message_new_method_call(DBUS_SERVICE_DBUS, DBUS_PATH_DBUS,
			DBUS_INTERFACE_DBUS, "UpdateActivationEnvironment");
	if (NULL == msg)
	  {
	    fprintf(stderr, "UpdateActivationEnvironment failed: Message Null\n");
	    exit(EXIT_CODE_FATAL_ERORR);
	  }

	dbus_message_iter_init_append(msg, &array_iter);

	if (!dbus_message_iter_open_container(&array_iter, DBUS_TYPE_ARRAY, "{ss}",	&dict_iter))
	  {
	    fprintf(stderr, "dbus_message_iter_open_container - failed");
	    exit(EXIT_CODE_FATAL_ERORR);
	  }

	if (!dbus_message_iter_open_container(&dict_iter, DBUS_TYPE_DICT_ENTRY,
			NULL, &dict_entry_iter))
	  {
	    fprintf(stderr, "dbus_message_iter_open_container - failed");
	    exit(EXIT_CODE_FATAL_ERORR);
	  }

	if (!dbus_message_iter_append_basic(&dict_entry_iter, DBUS_TYPE_STRING,
			&key))
	  {
	    fprintf(stderr, "dbus_message_iter_append_basic - failed");
	    exit(EXIT_CODE_FATAL_ERORR);
	  }

	if (!dbus_message_iter_append_basic(&dict_entry_iter, DBUS_TYPE_STRING,
			&value))
	  {
	    fprintf(stderr, "dbus_message_iter_append_basic - failed");
	    exit(EXIT_CODE_FATAL_ERORR);
	  }

	dbus_message_iter_close_container(&dict_iter, &dict_entry_iter);
	dbus_message_iter_close_container(&array_iter, &dict_iter);

	if (!dbus_connection_send_with_reply(conn, msg, &pending, DBUS_TIMEOUT_INFINITE))
	  {
	    fprintf(stderr, "UpdateActivationEnvironment: Out Of Memory!\n");
	    exit(EXIT_CODE_FATAL_ERORR);
	  }
	if (NULL == pending)
	  {
	    fprintf(stderr, "UpdateActivationEnvironment: Pending Call Null\n");
	    exit(EXIT_CODE_FATAL_ERORR);
	  }
	dbus_connection_flush(conn);

	printf("UpdateActivationEnvironment: Request Sent...\n");

	// free message
	dbus_message_unref(msg);

	// block until we receive a reply
	dbus_pending_call_block(pending);

	// get the reply message
	msg = dbus_pending_call_steal_reply(pending);
	if (NULL == msg)
	  {
	    fprintf(stderr, "UpdateActivationEnvironment: Reply Null\n");
	    exit(EXIT_CODE_FATAL_ERORR);
	  }
	else
		printf("UpdateActivationEnvironment confirmed!\n");
	// free the pending message handle
	dbus_pending_call_unref(pending);
	dbus_message_unref(msg);

	return TRUE;
}

// Signals
void sendSignal(const char *sigName, const char *sigValue)
{
	DBusMessage *msg;
	DBusMessageIter args;
	DBusConnection *conn;
	DBusError err;
	unsigned int serial = 0;

	dbus_error_init(&err); // initialize the error value
//	conn = connectWithName(SIGNAL_SERVER_NAME, &err);
	conn = connectWithName(NULL, &err);
  if (dbus_error_is_set(&err))
    {
      fprintf(stderr,"Connecting failed - %s\n", err.message);
      dbus_error_free(&err);
      exit(EXIT_CODE_FATAL_ERORR);
    }

	// create a signal & check for errors
	msg = dbus_message_new_signal(TEST_SIGNAL_PATH, // object name of the signal
			TEST_SIGNAL_INTERFACE, // interface name of the signal
			sigName); // name of the signal
	if (NULL == msg)
	  {
	    fprintf(stderr,"Creating new message failed\n");
	    exit(EXIT_CODE_FATAL_ERORR);
	  }

	// append arguments onto signal
	dbus_message_iter_init_append(msg, &args);
	if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &sigValue))
	  {
	    fprintf(stderr,"Out Of Memory!\n");
	    exit(EXIT_CODE_FATAL_ERORR);
	  }

  printf("Sending signal with value \"%s\"\n", sigValue);

	// send the message and flush the connection
	if (!dbus_connection_send(conn, msg, &serial))
	  {
	    fprintf(stderr, "Out Of Memory while trying to send message!\n");
	    exit(EXIT_CODE_FATAL_ERORR);
	  }

	dbus_connection_flush(conn);
	printf("Signal Sent\n");

	// free the message and close the connection
	dbus_message_unref(msg);
	dbus_connection_unref(conn);
}

void receiveSignal(unsigned int flags, const char *rule)
{
	DBusMessage *msg;
	DBusConnection *conn;
	DBusError err;

	dbus_error_init(&err); // initialize the errors
	conn = connectWithName(SIGNAL_SERVER_NAME, &err);
  if (dbus_error_is_set(&err))
    {
      fprintf(stderr, "Connecting failed - %s\n", err.message);
      dbus_error_free(&err);
      exit(EXIT_CODE_FATAL_ERORR);
    }

  if (flags & FLAG_RELEASE_NAME)
    releaseName(conn, SIGNAL_SERVER_NAME);

  // add a rule for which messages we want to see
	dbus_bus_add_match(conn, rule, &err);
	if (dbus_error_is_set(&err))
	{
		fprintf(stderr, "Adding match failed (%s)\n", err.message);
		dbus_error_free(&err);
		exit(EXIT_CODE_FATAL_ERORR);
	}

	if(flags & FLAG_ADD_MATCH_ORG_FREEDESKTOP_DBUS)
	  {
	    dbus_bus_add_match(conn, "type='signal',interface='org.freedesktop.DBus'", &err);
	    if (dbus_error_is_set(&err))
	    {
	      fprintf(stderr, "Adding match failed (%s)\n", err.message);
	      dbus_error_free(&err);
	      exit(EXIT_CODE_FATAL_ERORR);
	    }
	  }

	dbus_connection_flush(conn);
	if (dbus_error_is_set(&err))
	  {
	    fprintf(stderr, "Flush Error (%s)\n", err.message);
	    dbus_error_free(&err);
	    exit(EXIT_CODE_FATAL_ERORR);
	  }
	printf("Match rule sent\n");

	if(flags & FLAG_RELEASE_MATCH)
	  {
	    dbus_bus_remove_match(conn, rule, &err);
	    if (dbus_error_is_set(&err))
	    {
	      fprintf(stderr, "Match release failed(%s)\n", err.message);
	      dbus_error_free(&err);
	      exit(EXIT_CODE_FATAL_ERORR);
	    }

      printf("Match released correctly.\n");
	  }

	printf("Listening for signals...\n");
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
          continue;
        }

      // check if the message is a signal from the correct interface and with the correct name
      if (dbus_message_is_signal(msg, TEST_SIGNAL_INTERFACE, TEST_SIGNAL_NAME))
        {
          printf("Message serial: %u, reply_serial: %u, sender: %s\n",
              dbus_message_get_serial(msg),
              dbus_message_get_reply_serial(msg),
              dbus_message_get_sender(msg));

          printf("Got Signal with value \"%s\"\n", readStringFromMsg(msg));
        }
      else if (dbus_message_is_signal(msg, DBUS_INTERFACE_DBUS, "NameOwnerChanged"))
        printf("Got NameOwnerChangedSignal for name %s.\n", readStringFromMsg(msg));
      else if (dbus_message_is_signal(msg, DBUS_INTERFACE_DBUS, "NameAcquired"))
        printf("Got NameAcquired 'signal' for name %s.\n", readStringFromMsg(msg));
      else if (dbus_message_is_signal(msg, DBUS_INTERFACE_DBUS, "NameLost"))
        printf("Got NameLost 'signal' for name %s.\n", readStringFromMsg(msg));
      else
        printf("Got signal %s.\n", dbus_message_get_member(msg));

      // free the message
      dbus_message_unref(msg);
    }
	// close the connection
	dbus_connection_close(conn);
}

// Methods
void sendMethodCall(const char *methodName, const char *param, char* upd_env, unsigned int flags)
{
	DBusMessage *msg;
	DBusMessageIter args, subargs;
	DBusConnection *conn;
	DBusError err;
	DBusPendingCall *pending;
	unsigned int replyValue1;
	unsigned int replyValue2;
  const char *pServerAddress = METHOD_SERVER_NAME;

	printf("Calling remote method \"%s\" with param: \"%s\"\n", methodName, param);

	dbus_error_init(&err);
	conn = connectWithName(NULL, &err);

	if(flags & FLAG_GET_BUS_ID)
	  {
      char* pUuid;

	    pending = methodDBusNoArgs(conn, "GetId");
	    dbus_pending_call_block(pending);  // block until we receive a reply
	    msg = getMessageNoError(pending);
      if (!dbus_message_iter_init(msg, &args))
        {
          fprintf(stderr, "Message has no arguments!\n");
          exit(EXIT_CODE_FATAL_ERORR);
        }
      if (DBUS_TYPE_STRING != dbus_message_iter_get_arg_type(&args))
        {
          fprintf(stderr, "Argument is not string\n");
          exit(EXIT_CODE_FATAL_ERORR);
        }
      else
        dbus_message_iter_get_basic(&args, &pUuid);

      printf("Got Reply: id of bus is '%s'\n", pUuid);
      dbus_message_unref(msg);
	  }

	if(flags & FLAG_GET_SELINUX_SECURITY)
	  {
      char* pName;

	    pending = methodDBusWArg(conn, "GetConnectionSELinuxSecurityContext", DBUS_TYPE_STRING, &pServerAddress);
	    dbus_pending_call_block(pending); // block until we receive a reply
	    msg = getMessageNoError(pending);
      if (!dbus_message_iter_init(msg, &args))
        {
          fprintf(stderr, "Message has no arguments!\n");
          exit(EXIT_CODE_FATAL_ERORR);
        }
	    if (DBUS_TYPE_ARRAY != dbus_message_iter_get_arg_type(&args))
	      {
	        fprintf(stderr, "Argument is not array!\n");
	        exit(EXIT_CODE_FATAL_ERORR);
	      }
      else
        {
          int len;
          int* pLen = &len;

          if (DBUS_TYPE_BYTE != dbus_message_iter_get_element_type(&args))
            {
              fprintf(stderr, "Argument is not byte! it is %c\n", (char)dbus_message_iter_get_element_type(&args));
              exit(EXIT_CODE_FATAL_ERORR);
            }
          dbus_message_iter_recurse(&args, &subargs);
          if(!dbus_type_is_fixed(dbus_message_iter_get_element_type(&args)))
            {
              fprintf(stderr, "Argument is not fixed!\n");
              exit(EXIT_CODE_FATAL_ERORR);
            }
          dbus_message_iter_get_fixed_array(&subargs, &pName, pLen);
            printf("Got Reply: GetConnectionSELinuxSecurityContext of '%s' is (%d)'%s'\n", pServerAddress, len, pName);
        }
      dbus_message_unref(msg);
	  }

	if(flags & FLAG_LIST_NAMES)
	  {
	    char *str = NULL;
      int i = 0;

	    pending = methodDBusNoArgs(conn, "ListNames");
	    dbus_pending_call_block(pending);  // block until we receive a reply
	    msg = getMessageNoError(pending);
      if (!dbus_message_iter_init(msg, &args))
        {
          fprintf(stderr, "Message has no arguments!\n");
          exit(EXIT_CODE_FATAL_ERORR);
        }
      do
        {
          char showPrv = 1;

          if (DBUS_TYPE_ARRAY == dbus_message_iter_get_arg_type(&args))
            {
              DBusMessageIter array_iter;
              dbus_message_iter_recurse(&args, &array_iter);
              printf("\nName list:\n");

              while (dbus_message_iter_get_arg_type(&array_iter) == DBUS_TYPE_STRING)
                {
                  dbus_message_iter_get_basic(&array_iter, &str);
                  dbus_message_iter_next(&array_iter);

                  if (str[0] != ':' || showPrv)
                    printf("   %s\n", str);
                }
            }
          else
            {
              fprintf(stderr, "Argument %d is not an array!\n", i);
              exit (1);
            }

          i++;
        } while (dbus_message_iter_next(&args));
      dbus_message_unref(msg);
      printf("Done.\n");
	  }

  if(flags & FLAG_GET_SERVER_OWNER)
    {
      char* pName;

      pending = methodDBusWArg(conn, "GetNameOwner", DBUS_TYPE_STRING, &pServerAddress);
      dbus_pending_call_block(pending); // block until we receive a reply
      msg = getMessageNoError(pending);
      if (!dbus_message_iter_init(msg, &args))
        {
          fprintf(stderr, "Message has no arguments!\n");
          exit(EXIT_CODE_FATAL_ERORR);
        }
      if (DBUS_TYPE_STRING != dbus_message_iter_get_arg_type(&args))
        {
          fprintf(stderr, "Argument is not string!\n");
          exit(EXIT_CODE_FATAL_ERORR);
        }
      dbus_message_iter_get_basic(&args, &pName);
      printf("Got Reply: Id of '%s' is '%s'\n", pServerAddress, pName);
      dbus_message_unref(msg);
    }

  if(flags & FLAG_SERVER_HAS_OWNER)
    {
      dbus_bool_t result;

      pending = methodDBusWArg(conn, "NameHasOwner", DBUS_TYPE_STRING, &pServerAddress);
      dbus_pending_call_block(pending); // block until we receive a reply
      msg = getMessageNoError(pending);
      if (!dbus_message_iter_init(msg, &args))
        {
          fprintf(stderr, "Message has no arguments!\n");
          exit(EXIT_CODE_FATAL_ERORR);
        }
      if (DBUS_TYPE_BOOLEAN != dbus_message_iter_get_arg_type(&args))
        {
          fprintf(stderr,"Argument is not bool!\n");
          exit (1);
        }
      dbus_message_iter_get_basic(&args, &result);
      printf("Got Reply: HasNameOwner '%s' result is '%d'\n", pServerAddress, result);
      dbus_message_unref(msg);
	}

  if(flags & FLAG_GET_SERVER_UNIX_USER)
    {
      dbus_uint32_t uid;

      pending = methodDBusWArg(conn, "GetConnectionUnixUser", DBUS_TYPE_STRING, &pServerAddress); //&pUniqueName);
      dbus_pending_call_block(pending);// block until we receive a reply
      msg = getMessageNoError(pending);
      if (!dbus_message_iter_init(msg, &args))
        {
          fprintf(stderr, "Message has no arguments!\n");
          exit(EXIT_CODE_FATAL_ERORR);
        }
      if (DBUS_TYPE_UINT32 != dbus_message_iter_get_arg_type(&args))
        {
          fprintf(stderr,"Argument is not string!\n");
          exit(EXIT_CODE_FATAL_ERORR);
        }
      dbus_message_iter_get_basic(&args, &uid);
      printf("Got Reply: Uid of '%s' is '%d'\n", pServerAddress, uid);
      dbus_message_unref(msg);
    }

  if(flags & FLAG_GET_SERVER_PID)
    {
      dbus_uint32_t uid;

      pending = methodDBusWArg(conn, "GetConnectionUnixProcessID", DBUS_TYPE_STRING, &pServerAddress); //&pUniqueName);
      dbus_pending_call_block(pending);// block until we receive a reply
      msg = getMessageNoError(pending);
      if (!dbus_message_iter_init(msg, &args))
        {
          fprintf(stderr, "Message has no arguments!\n");
          exit(EXIT_CODE_FATAL_ERORR);
        }
      if (DBUS_TYPE_UINT32 != dbus_message_iter_get_arg_type(&args))
        {
          fprintf(stderr,"Argument is not string!\n");
          exit(EXIT_CODE_FATAL_ERORR);
        }
      dbus_message_iter_get_basic(&args, &uid);
      printf("Got Reply: Pid of '%s' is '%d'\n", pServerAddress, uid);
      dbus_message_unref(msg);
    }

  if(flags & FLAG_GET_SERVER_CREDS)
    {
      pending = methodDBusWArg(conn, "GetConnectionCredentials", DBUS_TYPE_STRING, &pServerAddress);
      dbus_pending_call_block(pending); // block until we receive a reply
      msg = getMessageNoError(pending);
      printf("Got non-error reply for GetConnectionCredentials but no-one coded me how to understand it\n");
      dbus_message_unref(msg);
    }

  if(flags & FLAG_LIST_ACTIVATABLE)
    {
      char *str = NULL;
      int i = 0;

      pending = methodDBusNoArgs(conn, "ListActivatableNames");
      dbus_pending_call_block(pending);  // block until we receive a reply
      msg = getMessageNoError(pending);
      if (!dbus_message_iter_init(msg, &args))
        {
          fprintf(stderr,"Message has no parameters\n");
          exit(EXIT_CODE_FATAL_ERORR);
        }
      do
        {
          char showPrv = 0;

          if (DBUS_TYPE_ARRAY == dbus_message_iter_get_arg_type(&args))
            {
              DBusMessageIter array_iter;
              dbus_message_iter_recurse(&args, &array_iter);
              printf("\nName list:\n");

              while (dbus_message_iter_get_arg_type(&array_iter) == DBUS_TYPE_STRING)
                {
                  dbus_message_iter_get_basic(&array_iter, &str);
                  dbus_message_iter_next(&array_iter);

                  if(str[0]!=':' || showPrv)
                    printf("   %s\n", str);
                }
            }
          else
            {
              printf("Argument %d is not an array!\n", i);
              exit(EXIT_CODE_FATAL_ERORR);
            }
          i++;
        }
        while(dbus_message_iter_next(&args));
      dbus_message_unref(msg);
      printf("Done.\n");
    }

  if(flags & FLAG_UPDATE_ACTIVATION_ENV)
    updActEnv(conn, upd_env);

  if(flags & FLAG_ACTIVATE)
    {
      dbus_uint32_t ret;

      msg = dbus_message_new_method_call(DBUS_SERVICE_DBUS, DBUS_PATH_DBUS, DBUS_INTERFACE_DBUS,
                                          "StartServiceByName");
      if (msg == NULL)
        {
          fprintf(stderr, "Message Null\n");
          exit(EXIT_CODE_FATAL_ERORR);
        }

      dbus_message_iter_init_append(msg, &args);
      if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &pServerAddress))
        {
          fprintf(stderr, "Out Of Memory!\n");
          exit(EXIT_CODE_FATAL_ERORR);
        }
      if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_UINT32, &replyValue1)) //this value has no meaning
        {
          fprintf(stderr, "Out Of Memory!\n");
          exit(EXIT_CODE_FATAL_ERORR);
        }

      if (!dbus_connection_send_with_reply (conn, msg, &pending, 15000))// -1 is default timeout
        {
          fprintf(stderr, "Sending with reply failed\n");
          exit(EXIT_CODE_FATAL_ERORR);
        }
      if (NULL == pending)
        {
          fprintf(stderr, "Pending Call Null\n");
          exit(EXIT_CODE_FATAL_ERORR);
        }
      dbus_connection_flush(conn);

      printf("StartServiceByName sent...\n");
      dbus_message_unref(msg);  // free message
      dbus_pending_call_block(pending);// block until we receive a reply

      msg = getMessageNoError(pending);
      if (!dbus_message_iter_init(msg, &args))
        {
          fprintf(stderr,"Message has no parameters\n");
          exit(EXIT_CODE_FATAL_ERORR);
        }
      if (DBUS_TYPE_UINT32 != dbus_message_iter_get_arg_type(&args))
        {
          fprintf(stderr,"Argument is not string!\n");
          exit(EXIT_CODE_FATAL_ERORR);
        }
      else
        dbus_message_iter_get_basic(&args, &ret);
      dbus_message_unref(msg);

      if(ret == 1)
        printf("Got Reply: DBUS_START_REPLY_SUCCESS\n");
      else if (ret == 2)
        printf("Got Reply: DBUS_START_REPLY_ALREADY_RUNNING\n");
      else
        {
          printf("Got strange reply: %d\n", ret);
          exit(EXIT_CODE_FATAL_ERORR);
        }
    }

	// create a new method call and check for errors
	msg = dbus_message_new_method_call(pServerAddress, // target for the method call
			TEST_METHOD_PATH, // object to call on
			TEST_METHOD_INTERFACE, // interface to call on
			methodName); // method name
	if (NULL == msg)
	  {
	    fprintf(stderr, "Message Null\n");
	    exit(EXIT_CODE_FATAL_ERORR);
	  }

	// append arguments
	dbus_message_iter_init_append(msg, &args);
	if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &param))
	  {
	    fprintf(stderr, "Out Of Memory!\n");
	    exit(EXIT_CODE_FATAL_ERORR);
	  }

	// send message and get a handle for a reply
	if (!dbus_connection_send_with_reply(conn, msg, &pending, -1)) // -1 is default timeout
    {
      fprintf(stderr, "Sending with reply failed!\n");
      exit(EXIT_CODE_FATAL_ERORR);
    }
	if (NULL == pending)
	  {
      fprintf(stderr, "Pending Call Null\n");
      exit(EXIT_CODE_FATAL_ERORR);
    }
	dbus_connection_flush(conn);
	dbus_message_unref(msg);
	printf("Request Sent...\n");

	dbus_pending_call_block(pending);      // block until we receive a reply

	msg = getMessageNoError(pending);
  if (!dbus_message_iter_init(msg, &args))
    {
      fprintf(stderr,"Message has no arguments\n");
      exit(EXIT_CODE_FATAL_ERORR);
    }
  if (DBUS_TYPE_UINT32 != dbus_message_iter_get_arg_type(&args))
    {
      fprintf(stderr, "Argument is not int!\n");
      exit(EXIT_CODE_FATAL_ERORR);
    }
  else
    dbus_message_iter_get_basic(&args, &replyValue1);

  if (!dbus_message_iter_next(&args))
    {
      fprintf(stderr, "Message has too few arguments!\n");
      exit(EXIT_CODE_FATAL_ERORR);
    }
  else if (DBUS_TYPE_UINT32 != dbus_message_iter_get_arg_type(&args))
    {
      fprintf(stderr, "Argument is not int!\n");
      exit(EXIT_CODE_FATAL_ERORR);
    }
  else
    dbus_message_iter_get_basic(&args, &replyValue2);

  printf("Got Reply: %X %X\n", replyValue1, replyValue2);
  dbus_message_unref(msg);

	dbus_connection_unref(conn);
}

void replyToMethodCall(DBusMessage *msg, DBusConnection *conn)
{
	DBusMessage *reply;
	DBusMessageIter args;
	unsigned int retValue1 = 0xDEAD;
	unsigned int retValue2 = 0xBEEF;
	unsigned int serial = 0;
	char *param = "";

	// read the arguments
	if (!dbus_message_iter_init(msg, &args))
		fprintf(stderr, "Message has no arguments!\n");
	else if (DBUS_TYPE_STRING != dbus_message_iter_get_arg_type(&args))
		fprintf(stderr, "Argument is not string!\n");
	else
		dbus_message_iter_get_basic(&args, &param);

	printf("Method called with \"%s\". \n", param);

	// create a reply from the message
	reply = dbus_message_new_method_return(msg);
	if(reply == NULL)
	  {
	    fprintf(stderr, "Error - reply is NULL\n");
	    exit(EXIT_CODE_FATAL_ERORR);
	  }

	// add the arguments to the reply
	dbus_message_iter_init_append(reply, &args);
	if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_UINT32, &retValue1))
	  {
	    fprintf(stderr, "Out Of Memory!\n");
	    exit(EXIT_CODE_FATAL_ERORR);
	  }

	if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_UINT32, &retValue2))
	  {
	    fprintf(stderr, "Out Of Memory!\n");
	    exit(EXIT_CODE_FATAL_ERORR);
	  }

	// send the reply && flush the connection
	if (!dbus_connection_send(conn, reply, &serial))
	  {
	    fprintf(stderr, "Out Of Memory!\n");
	    exit(EXIT_CODE_FATAL_ERORR);
	  }

	printf("Reply sent: %X %X\n", retValue1, retValue2);

	dbus_connection_flush(conn);

	// free the reply
	dbus_message_unref(reply);
}

void receiveMethodCall(const char *methodName, unsigned int flags)
{
	DBusMessage *msg;
	DBusMessageIter args;
	DBusConnection *conn;
	DBusError err;
	DBusPendingCall *pending;
  const char *pServerAddress = METHOD_SERVER_NAME;

	dbus_error_init(&err);
	conn = connectWithName(pServerAddress, &err);

	if(flags & FLAG_LIST_QUEUED)
	  {
      char *str = NULL;
      int i = 0;

	    pending = methodDBusWArg(conn, "ListQueuedOwners", DBUS_TYPE_STRING, &pServerAddress);
	    dbus_pending_call_block(pending);  // block until we receive a reply
	    msg = getMessageNoError(pending);
      dbus_message_iter_init(msg, &args);
      do
        {
          if (DBUS_TYPE_ARRAY == dbus_message_iter_get_arg_type(&args))
	          {
	            DBusMessageIter array_iter;
	            dbus_message_iter_recurse(&args, &array_iter);
	            printf("\nQueued Names list:\n");

	            while (dbus_message_iter_get_arg_type(&array_iter) == DBUS_TYPE_STRING)
	              {
	                dbus_message_iter_get_basic(&array_iter, &str);
	                dbus_message_iter_next(&array_iter);
	                printf("   %s\n", str);
	              }
	          }
	        else
	          {
	            fprintf(stderr, "Argument %d is not an array!\n", i);
	            exit(EXIT_CODE_FATAL_ERORR);
	          }
	        i++;
	      } while (dbus_message_iter_next(&args));
	    dbus_message_unref(msg);
	    printf("Done.\n");
	  }

	if(flags & FLAG_RELEASE_NAME)
	  releaseName(conn, METHOD_SERVER_NAME);

	printf("Listening for method '%s' calls... \n", methodName);

	// loop, testing for new messages
	while (true)
	  {
	    dbus_connection_read_write(conn, 0);      // non blocking read of the next available message
	    msg = dbus_connection_pop_message(conn);

      // loop again if we haven't got a message
      if (NULL == msg)
        {
          usleep(1000);
          continue;
        }

		// check this is a method call for the right interface & method
		if (dbus_message_is_method_call(msg, "test.method.Type", methodName))
		  {
		    if(flags & FLAG_DELAY_ANSWER)
		      sleep(35);
		    replyToMethodCall(msg, conn);
		}

		if (dbus_message_get_type(msg) == DBUS_MESSAGE_TYPE_ERROR)
			printErrorReply(msg, &err);

		// free the message
		dbus_message_unref(msg);
	}

	// close the connection
	dbus_connection_close(conn);
}

int main(int argc, char **argv)
{
	int i;
	const char *arg;

	if (argc == 1)
	  {
	    receiveMethodCall(TEST_METHOD_NAME, 0);
	    return EXIT_CODE_SUCCESS;
	  }
	else if (0 == strcmp(argv[1], "ssnd"))               // SIGNAL SEND
	  {
	    const char *sigName = NULL;
	    const char *sigText = NULL;

	    i = 2;
	    while (i < argc)
	      {
	        arg = argv[i++];
	        if (strcmp (arg, "--help") == 0)
	          {
	            printf("Signal Send help:\n");
	            printf("With no args sends signal to path '%s', inteface '%s', signal name '%s'\n", TEST_SIGNAL_PATH, TEST_SIGNAL_INTERFACE, TEST_SIGNAL_NAME);
	            printf("signal value 'Radek'. Name can be changed with param --name= and value with --value=\n");
	            return EXIT_CODE_WRONG_PROGRAM_ARGUMENTS;
	          }
	        else if (strstr (arg, "--name=") == arg)
	          {
	            sigName = strchr (arg, '=');
	            ++sigName;
	          }
          else if (strstr (arg, "--value=") == arg)
            {
              sigText = strchr (arg, '=');
              ++sigText;
            }
          else
            {
              printf("Unrecognized option %s\n", arg);
              return EXIT_CODE_WRONG_PROGRAM_ARGUMENTS;
            }
	      }

      if(sigName == NULL)
        sigName = TEST_SIGNAL_NAME;
      if(sigText == NULL)
        sigText = "Radek";

      sendSignal(sigName, sigText);
      return EXIT_CODE_SUCCESS;
	  }
  else if (0 == strcmp(argv[1], "srcv"))          // SIGNAL RECEIVE
    {
      const char *rule = NULL;
      unsigned int flags = 0;

      i = 2;
      while (i < argc)
        {
          arg = argv[i++];
          if (strcmp (arg, "--help") == 0)
            {
              printf("Signal receive help:\n");
              printf("Acquires '%s' well-known-name and registers \"%s\" match rule, which can be altered with --rule= option\n", SIGNAL_SERVER_NAME, SIGNAL_SERVER_MATCH_RULE);
              printf("Additional option flags (for special test case scenarios):\n");
              printf("   --release-name   '%s' well-known name is released after being acquired, before match rule registration\n", SIGNAL_SERVER_NAME);
              printf("   --release-match  match rule is released just after being registered\n");
              printf("   --match-dbus     match rule \"type='signal',interface='org.freedesktop.DBus'\" is registered additionally\n");
              return EXIT_CODE_WRONG_PROGRAM_ARGUMENTS;
            }
          else if (strstr (arg, "--rule=") == arg)
            {
              rule = strchr (arg, '=');
              ++rule;
            }
          else if (strcmp (arg, "--release-name") == 0)
            flags |= FLAG_RELEASE_NAME;
          else if (strcmp (arg, "--release-match") == 0)
            flags |= FLAG_RELEASE_MATCH;
          else if (strcmp (arg, "--match-dbus") == 0)
            flags |= FLAG_ADD_MATCH_ORG_FREEDESKTOP_DBUS;
          else
            {
              printf("Unrecognized option %s\n", arg);
              return EXIT_CODE_WRONG_PROGRAM_ARGUMENTS;
            }
        }

      if(rule == NULL)
        rule = SIGNAL_SERVER_MATCH_RULE;

      receiveSignal(flags, rule);
      return EXIT_CODE_SUCCESS;
    }
	else if (0 == strcmp(argv[1], "msnd"))          // METHOD SEND
	  {
      const char *methodName = NULL;
      const char *methodText = NULL;
      char *upd_env = NULL;
      unsigned int flags = 0;

      i = 2;
      while (i < argc)
        {
          arg = argv[i++];
          if (strcmp (arg, "--help") == 0)
            {
              printf("Method Send help:\n");
              printf("With no args calls method '%s' with value '%s' from path /test/method/Object, inteface '%s'\n",
                  TEST_METHOD_NAME, TEST_METHOD_VALUE, TEST_METHOD_INTERFACE);
              printf("Method name can be changed with param --name= and value with --value=\n");
              printf("Additional option flags for special test case scenarios (executed before method call,\n");
              printf("error on them cause exit with code 2 if valid error reply was received):\n");
              printf("   --getbusid   calls GetId method of org.freedesktop.DBus\n");
              printf("   --listnames  calls ListNames method of org.freedesktop.DBus\n");
              printf("   --listactivatable  calls ListActivatableNames method of org.freedesktop.DBus\n");
              printf("   --getowner  calls GetNameOwner method of org.freedesktop.DBus for %s\n", METHOD_SERVER_NAME);
              printf("   --hasowner  calls NameHasOwner method of org.freedesktop.DBus for %s\n", METHOD_SERVER_NAME);
              printf("   --getunixuser  calls GetConnectionUnixUser method of org.freedesktop.DBus for %s\n", METHOD_SERVER_NAME);
              printf("   --getunixpid  calls GetConnectionUnixProcessID method of org.freedesktop.DBus for %s\n", METHOD_SERVER_NAME);
              printf("   --getcredentials  calls GetConnectionCredentials method of org.freedesktop.DBus for %s\n", METHOD_SERVER_NAME);
              printf("   --update-env= calls UpdateActivationEnvironment method of org.freedesktop.DBus with one key-value pair separated with '=' sign\n");
              printf("   --activate  calls StartServiceByName method of org.freedesktop.DBus for %s\n", METHOD_SERVER_NAME);
              printf("   --getselinuxsecuritycontext  calls GetConnectionSELinuxSecurityContext method"
                  "of org.freedesktop.DBus for %s\n", METHOD_SERVER_NAME);
              return EXIT_CODE_WRONG_PROGRAM_ARGUMENTS;
            }
          else if (strstr (arg, "--name=") == arg)
            {
              methodName = strchr (arg, '=');
              ++methodName;
            }
          else if (strstr (arg, "--value=") == arg)
            {
              methodText = strchr (arg, '=');
              ++methodText;
            }
          else if (strcmp (arg, "--getbusid") == 0)
            flags |= FLAG_GET_BUS_ID;
          else if (strcmp (arg, "--getselinuxsecuritycontext") == 0)
            flags |= FLAG_GET_SELINUX_SECURITY;
          else if (strcmp (arg, "--listnames") == 0)
            flags |= FLAG_LIST_NAMES;
          else if (strcmp (arg, "--listactivatable") == 0)
            flags |= FLAG_LIST_ACTIVATABLE;
          else if (strcmp (arg, "--getowner") == 0)
            flags |= FLAG_GET_SERVER_OWNER;
          else if (strcmp (arg, "--hasowner") == 0)
            flags |= FLAG_SERVER_HAS_OWNER;
          else if (strcmp (arg, "--getunixuser") == 0)
            flags |= FLAG_GET_SERVER_UNIX_USER;
          else if (strcmp (arg, "--getunixpid") == 0)
            flags |= FLAG_GET_SERVER_PID;
          else if (strcmp (arg, "--getcredentials") == 0)
            flags |= FLAG_GET_SERVER_CREDS;
          else if (strcmp (arg, "--activate") == 0)
            flags |= FLAG_ACTIVATE;
          else if (strstr (arg, "--update-env=") == arg)
            {
              char *equal;

              upd_env = strchr (arg, '=');
              ++upd_env;
              equal = strchr(upd_env, '=');
              if (equal == NULL)
                return EXIT_CODE_WRONG_PROGRAM_ARGUMENTS;
              flags |= FLAG_UPDATE_ACTIVATION_ENV;
            }
          else
            {
              printf("Unrecognized option %s\n", arg);
              return EXIT_CODE_WRONG_PROGRAM_ARGUMENTS;
            }
        }

      if(methodName == NULL)
        methodName = TEST_METHOD_NAME;
      if(methodText == NULL)
        methodText = TEST_METHOD_VALUE;

      sendMethodCall(methodName, methodText, upd_env, flags);
      return EXIT_CODE_SUCCESS;
	  }
	else if (0 == strcmp(argv[1], "mrcv"))          // METHOD RECEIVE
	  {
      const char *methodName = NULL;
	    unsigned int flags = 0;

      i = 2;
      while (i < argc)
        {
          arg = argv[i++];
          if (strcmp (arg, "--help") == 0)
            {
              printf("Method receive help:\n");
              printf("Acquires '%s' well-known-name and sends 'DEAD BEEF' response to '%s' method calls (if not altered by --name=)\n", METHOD_SERVER_NAME, TEST_METHOD_NAME);
              printf("Additional option flags (for special test case scenarios):\n");
              printf("   --release-name   '%s' well-known name is released after being acquired\n", METHOD_SERVER_NAME);
              printf("   --delayed-reply  delays sending response for 35s. which may trigger timeout for the reply receiver\n");
              printf("   --list-queued-owners  calls ListQueuedOwners method of org.freedesktop.DBus for '%s' name\n", METHOD_SERVER_NAME);
              return EXIT_CODE_WRONG_PROGRAM_ARGUMENTS;
            }
          else if (strstr (arg, "--name=") == arg)
            {
              methodName = strchr (arg, '=');
              ++methodName;
            }
          else if (strcmp (arg, "--release-name") == 0)
            flags |= FLAG_RELEASE_NAME;
          else if (strcmp (arg, "--delayed-reply") == 0)
            flags |= FLAG_DELAY_ANSWER;
          else if (strcmp (arg, "--list-queued-owners") == 0)
            flags |= FLAG_LIST_QUEUED;
          else
            {
              printf("Unrecognized option %s\n", arg);
              return EXIT_CODE_WRONG_PROGRAM_ARGUMENTS;
            }
        }

      if(methodName == NULL)
        methodName = TEST_METHOD_NAME;

      receiveMethodCall(methodName, flags);
      return EXIT_CODE_SUCCESS;
	  }
	else
	  {
	    printf("Syntax:\n\tserverClient [srcv|mrcv|ssnd|msnd] [--help]\n");
	    printf("\t\tsrcv - Signal Receive (signal server)\n");
	    printf("\t\tmrcv - Method Receive (method server)\n");
	    printf("\t\tssnd - Signal Send (signal client)\n");
	    printf("\t\tmsnd - Method Send (method client)\n");
	    printf("Check individual --help for each function's options and params possibilities\n");
	    printf("Return values:\n");
	    printf("\t0 - success\n");
	    printf("\t1 - DBus failure\n");
	    printf("\t2 - DBus correctly returned error reply from remote server or dbus-daemon\n");
	    printf("\t3 - invalid options or --help - tests not started\n");
	  }

	return EXIT_CODE_WRONG_PROGRAM_ARGUMENTS;
}
