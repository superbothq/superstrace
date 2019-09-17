#ifndef _WS_HANDLER_H_
#define _WS_HANDLER_H_

#include <libwebsockets.h>

struct lws_context *ws_init();
int ws_connect_client(struct lws_context *context, struct lws *wsi, const char *host, int port);
int ws_send_message(struct lws *receiver, const unsigned char *msg);

#endif
