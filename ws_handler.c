#include "ws_handler.h"

struct msg
{
  void *payload;
  size_t len;
};

static void destroy_message(void *_msg)
{
  struct msg *msg = _msg;

  free(msg->payload);
  msg->payload = NULL;
  msg->len = 0;
}

static const struct lws_protocols protocols[] = {
    {
        "protocol",
        ws_callback,
        0,
        0,
    },
    {NULL, NULL, 0, 0}};

static int ws_callback(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len)
{
  printf("callback reason: %d\n", reason);
}

struct lws_context *ws_init()
{
  struct lws_context_creation_info info;
  struct lws_protocols protocol;
  struct lws_context *context;

  memset(&info, 0, sizeof(info));
  info.port = CONTEXT_PORT_NO_LISTEN;
  info.protocols = &protocols;

  context = lws_create_context(&info);
  if (!context)
  {
    fprintf(stderr, "Failed to create lws context!\n");
    exit(1);
  }

  return context;
}

int ws_connect_client(struct lws_context *context, struct lws *wsi, const char *host, int port)
{
  struct lws_client_connect_info conn_info;

  conn_info.context = context;
  conn_info.port = port;
  conn_info.address = "localhost";
  conn_info.path = "/";
  conn_info.host = host;
  conn_info.origin = host;
  conn_info.protocol = "protocol";
  conn_info.pwsi = wsi;

  return !lws_client_connect_via_info(&conn_info);
}

int ws_send_message(struct lws *receiver, const unsigned char *msg)
{
  struct lws_write_passthru message;
  message.wsi = receiver;
  message.buf = msg;
  message.len = strlen(msg);
  message.wp = LWS_WRITE_TEXT;

  return lws_write(receiver, msg, strlen(msg), LWS_WRITE_TEXT);
}
