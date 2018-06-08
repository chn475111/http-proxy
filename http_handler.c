#include "log.h"
#include "connection.h"
#include "http_handler.h"

static void http_url_dump(const char *url, const struct http_parser_url *u)
{
    unsigned int i = 0;

    log_debug("field_set: 0x%x, port: %u", u->field_set, u->port);
    for(i = 0; i < UF_MAX; i++)
    {
        if((u->field_set & (1 << i)) == 0)
        {
          log_debug("field_data[%u]: unset", i);
          continue;
        }

        log_debug("field_data[%u]: offset: %u, length: %u, value: %.*s", i,
            u->field_data[i].off,
            u->field_data[i].len,
            u->field_data[i].len,
            url + u->field_data[i].off);
    }
}

http_t *http_new(void *data)
{
    http_t *h = (http_t*)malloc(sizeof(http_t));
    if(h == NULL)
    {
        log_err("malloc memory failed - %d: %s", errno, strerror(errno));
        return NULL;
    }
    memset(h, 0, sizeof(http_t));

    http_parser_settings_init(&h->settings);
    h->settings.on_message_begin = on_message_begin;
    h->settings.on_url = on_url;
    h->settings.on_status = on_status;
    h->settings.on_header_field = on_header_field;
    h->settings.on_header_value = on_header_value;
    h->settings.on_headers_complete = on_headers_complete;
    h->settings.on_body = on_body;
    h->settings.on_message_complete = on_message_complete;
    h->settings.on_chunk_header = on_chunk_header;
    h->settings.on_chunk_complete = on_chunk_complete;

    http_parser_init(&h->parser, HTTP_BOTH);
    h->parser.data = data;
    return h;
}

int http_exec(http_t *h, const char *buf, int len)
{
    int ret = http_parser_execute(&h->parser, &h->settings, buf, len);
    if(ret != len)
    {
        log_err("http parser failed - %s: %s", http_errno_name(HTTP_PARSER_ERRNO(&h->parser)), http_errno_description(HTTP_PARSER_ERRNO(&h->parser)));
        return -1;
    }
    return 0;
}

void http_delete(http_t *h)
{
    if(h) free(h);
}

int on_message_begin(http_parser *parser)
{
    connection_t *conn = (connection_t*)parser->data;
    if(conn == NULL)
        return -1;
    memset(&conn->http->data, 0, sizeof(http_data_t));

    log_debug("***MESSAGE BEGIN***");
    return 0;
}

int on_url(http_parser *parser, const char *at, size_t length)
{
    connection_t *conn = (connection_t*)parser->data;
    if(conn == NULL || at == NULL)
        return -1;
    http_header_t *url = &conn->http->data.head.url;

    memcpy(url->buffer + url->length, at, length);
    url->length += length;

    log_debug("HTTP Url - %d: %.*s", (int)length, (int)length, at);
    return 0;
}

int on_status(http_parser *parser, const char *at, size_t length)
{
    connection_t *conn = (connection_t*)parser->data;
    if(conn == NULL || at == NULL)
        return -1;
    http_header_t *status = &conn->http->data.head.status;

    memcpy(status->buffer + status->length, at, length);
    status->length += length;

    log_debug("HTTP Status - %d: %.*s", (int)length, (int)length, at);
    return 0;
}

int on_header_field(http_parser *parser, const char *at, size_t length)
{
    connection_t *conn = (connection_t*)parser->data;
    if(conn == NULL || at == NULL)
        return -1;

    log_debug("Header field - %d: %.*s", (int)length, (int)length, at);
    return 0;
}

int on_header_value(http_parser *parser, const char *at, size_t length)
{
    connection_t *conn = (connection_t*)parser->data;
    if(conn == NULL || at == NULL)
        return -1;

    log_debug("Header value - %d: %.*s", (int)length, (int)length, at);
    return 0;
}

int on_headers_complete(http_parser *parser)
{
    connection_t *conn = (connection_t*)parser->data;
    if(conn == NULL)
        return -1;
    http_header_t *url = &conn->http->data.head.url;

    int ret = 0;
    struct http_parser_url u;

    http_parser_url_init(&u);
    ret = http_parser_parse_url(url->buffer, url->length, 0, &u);
    if(ret != 0)
    {
        log_err("http url parse failed - %d", ret);
        return -1;
    }
    http_url_dump(url->buffer, &u);

    log_debug("***HEADERS COMPLETE***");
    return 0;
}

int on_body(http_parser *parser, const char *at, size_t length)
{
    connection_t *conn = (connection_t*)parser->data;
    if(conn == NULL || at == NULL)
        return -1;
    
    log_debug("Body value - %d: %.*s", (int)length, (int)length, at);
    return 0;
}

int on_message_complete(http_parser *parser)
{
    connection_t *conn = (connection_t*)parser->data;
    if(conn == NULL)
        return -1;

    log_debug("***MESSAGE COMPLETE***");
    return 0;
}

int on_chunk_header(http_parser *parser)
{
    connection_t *conn = (connection_t*)parser->data;
    if(conn == NULL)
        return -1;

    log_debug("***CHUNK HEADER***");
    return 0;
}

int on_chunk_complete(http_parser *parser)
{
    connection_t *conn = (connection_t*)parser->data;
    if(conn == NULL)
        return -1;

    log_debug("***CHUNK COMPLETE***");
    return 0;
}
