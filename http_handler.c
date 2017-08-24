#define _GNU_SOURCE
#include <string.h>
#include "log.h"
#include "tcp_utils.h"
#include "ssl_utils.h"
#include "worker.h"
#include "master.h"
#include "connection.h"
#include "http_handler.h"

static int hex2ascii(uint64_t hex, unsigned char *ascii)
{
    int i = sizeof(uint64_t);
    unsigned char *pos = ascii;
    unsigned char high = 0;
    unsigned char low = 0;

    while(i--)
    {
        high = (hex >> (i*8+4)) & 0x0f;
        low  = (hex >> (i*8+0)) & 0x0f;
        if((pos-ascii == 0) && (high == 0x00) && (low == 0x00))
            continue;

        if(pos-ascii != 0 || high != 0x00)
        {
            if((char)high >= 0 && (char)high <= 9)
                high += 0x30;
            else
                high += 0x37;
            *pos++ = high;
        }

        if((char)low >= 0 && (char)low <= 9)
            low += 0x30;
        else
            low += 0x57;
        *pos++ = low;
    }

    return pos - ascii;
}

int on_message_begin(http_parser *parser)
{
    connection_t *data = (connection_t*)parser->data;
    if(data == NULL)
        return -1;
    memset(&data->http->data, 0, sizeof(http_data_t));

    log_debug("***MESSAGE BEGIN***");
    return 0;
}

int on_url(http_parser *parser, const char *at, size_t length)
{
    connection_t *data = (connection_t*)parser->data;
    if(data == NULL || at == NULL)
        return -1;
    http_headers_t *headers = &data->http->data.headers;

    headers->type = parser->type;
    headers->r.request.method = parser->method;
    memcpy(headers->r.request.url.val + headers->r.request.url.len, at, length);
    headers->r.request.url.len += length;

    log_debug("HTTP Url - %d: %.*s", (int)length, (int)length, at);
    return 0;
}

int on_status(http_parser *parser, const char *at, size_t length)
{
    connection_t *data = (connection_t*)parser->data;
    if(data == NULL || at == NULL)
        return -1;
    http_headers_t *headers = &data->http->data.headers;

    headers->type = parser->type;
    headers->r.response.code = parser->status_code;
    memcpy(headers->r.response.status.val + headers->r.response.status.len, at, length);
    headers->r.response.status.len += length;

    log_debug("HTTP Status - %d: %.*s", (int)length, (int)length, at);
    return 0;
}

int on_header_field(http_parser *parser, const char *at, size_t length)
{
    connection_t *data = (connection_t*)parser->data;
    if(data == NULL || at == NULL)
        return -1;
    http_headers_t *headers = &data->http->data.headers;
    int count = headers->count;

    memcpy(headers->header[count].field.val + headers->header[count].field.len, at, length);
    headers->header[count].field.len += length;

    log_debug("Header field - %d: %.*s", (int)length, (int)length, at);
    return 0;
}

int on_header_value(http_parser *parser, const char *at, size_t length)
{
    connection_t *data = (connection_t*)parser->data;
    if(data == NULL || at == NULL)
        return -1;
    http_headers_t *headers = &data->http->data.headers;
    int count = headers->count;

    memcpy(headers->header[count].value.val + headers->header[count].value.len, at, length);
    headers->header[count].value.len += length;

    if(at[length] == '\r' || at[length] == '\n')
    {
        headers->count += 1;
        ///请求&响应重定向
        int fd = data->fd;
        int slot = data->slot;
        worker_t *work = container_of((void*)(data-fd), worker_t, conn);
        config_t *conf = &work->mast->conf;

        int isReqDirect = conf->ctrl[slot].isReqDirect;
        int isResDirect = conf->ctrl[slot].isResDirect;
        char *server_ip = conf->addr[slot].server_ip;
        short server_port = conf->addr[slot].server_port;
        char *backend_ip = conf->addr[slot].backend_ip;
        short backend_port = conf->addr[slot].backend_port;

        if(isReqDirect == 1 && headers->type == HTTP_REQUEST && strncasecmp("host", headers->header[count].field.val, headers->header[count].field.len) == 0)
            headers->header[count].value.len = sprintf(headers->header[count].value.val, "%s:%hu", backend_ip, backend_port);
        if(isReqDirect == 1 && headers->type == HTTP_REQUEST && strncasecmp("referer", headers->header[count].field.val, headers->header[count].field.len) == 0)
        {
            value_t *old = &headers->header[count].value;
            value_t new = {0, "\0"};
            char *p1 = NULL;               //双斜杠
            char *p2 = NULL;               //单斜杠

            p1 = strcasestr((char*)old->val, "//");
            if(p1)
            {
                p1 += 2;
                strncpy(new.val + new.len, old->val, p1 - old->val);
                new.len += p1 - old->val;

                new.len += sprintf(new.val + new.len, "%s:%hu", backend_ip, backend_port);

                p2 = strcasestr(p1, "/");
                if(p2)
                {
                    strncpy(new.val + new.len, p2, old->len - (p2 - old->val));
                    new.len += old->len - (p2 - old->val);
                }

                strncpy(old->val, new.val, new.len);
                old->len = new.len;
            }
        }
        if(isResDirect == 1 && headers->type == HTTP_RESPONSE && strncasecmp("server", headers->header[count].field.val, headers->header[count].field.len) == 0)
            headers->header[count].value.len = sprintf(headers->header[count].value.val, "%s:%hu", server_ip, server_port);
        if(isResDirect == 1 && headers->type == HTTP_RESPONSE && strncasecmp("location", headers->header[count].field.val, headers->header[count].field.len) == 0)
        {
            value_t *old = &headers->header[count].value;
            value_t new = {0, "\0"};
            char *p1 = NULL;               //双斜杠
            char *p2 = NULL;               //单斜杠

            p1 = strcasestr((char*)old->val, "//");
            if(p1)
            {
                p1 += 2;
                strncpy(new.val + new.len, old->val, p1 - old->val);
                new.len += p1 - old->val;

                new.len += sprintf(new.val + new.len, "%s:%hu", server_ip, server_port);

                p2 = strcasestr(p1, "/");
                if(p2)
                {
                    strncpy(new.val + new.len, p2, old->len - (p2 - old->val));
                    new.len += old->len - (p2 - old->val);
                }

                strncpy(old->val, new.val, new.len);
                old->len = new.len;
            }
        }
    }

    log_debug("Header value - %d: %.*s", (int)length, (int)length, at);
    return 0;
}


int on_headers_complete(http_parser *parser)
{
    connection_t *data = (connection_t*)parser->data;
    if(data == NULL)
        return -1;
    http_headers_t *headers = &data->http->data.headers;

    headers->major = parser->http_major;
    headers->minor = parser->http_minor;

    int i = 0;
    int rv = 0;
    char val[65536] = {0};
    char *pos = val;
    int fd = data->fd;
    int slot = data->slot;
    SSL *ssl = data->ssl;
    worker_t *work = container_of((void*)(data-fd), worker_t, conn);
    config_t *conf = &work->mast->conf;

    switch(headers->type)
    {
        case HTTP_REQUEST:
            pos += sprintf(pos, "%s ", http_method_str(headers->r.request.method));
            pos += sprintf(pos, "%.*s ", headers->r.request.url.len, headers->r.request.url.val);
            pos += sprintf(pos, "HTTP/%hu.%hu\r\n", headers->major, headers->minor);
            break;
        case HTTP_RESPONSE:
            pos += sprintf(pos, "HTTP/%hu.%hu ", headers->major, headers->minor);
            pos += sprintf(pos, "%u ", headers->r.response.code);
            pos += sprintf(pos, "%.*s\r\n", headers->r.response.status.len, headers->r.response.status.val);
            break;
        default:
            log_err("http type was unknown: %u", headers->type);
            return -1;
    }
    for(i = 0; i < headers->count; i ++)
    {
        pos += sprintf(pos, "%.*s: %.*s\r\n", headers->header[i].field.len, headers->header[i].field.val, headers->header[i].value.len, headers->header[i].value.val);
    }
    pos += sprintf(pos, "\r\n");

    if(headers->type == HTTP_REQUEST)
    {
        rv = tcp_send(fd, val, pos-val);
        if(rv != pos-val)
        {
            log_err("%s tcp send data to backend \"%s:%hu\" failed - %d: %s", conf->ctrl[slot].serverName, data->ip, data->port, errno, strerror(errno));
            return -1;
        }
        log_debug("2, %s tcp send data to backend \"%s:%hu\" succeed - %ld: %s", conf->ctrl[slot].serverName, data->ip, data->port, pos-val, val);
    }
    else
    {
        rv = ssl_write(ssl, val, pos-val);
        if(rv != pos-val)
        {
            log_err("%s ssl write data to frontend \"%s:%hu\" failed - %d: %s", conf->ctrl[slot].serverName, data->ip, data->port, errno, strerror(errno));
            return -1;
        }
        log_debug("4, %s ssl write data to frontend \"%s:%hu\" succeed - %ld: %s", conf->ctrl[slot].serverName, data->ip, data->port, pos-val, val);
    }

    if((int64_t)parser->content_length > 0)
    {
        http_body_t *body = &data->http->data.body;
        body->content_length = parser->content_length;
        body->val = NULL;
        body->len = 0;
    }

    log_debug("***HEADERS COMPLETE***");
    return 0;
}

int on_body(http_parser *parser, const char *at, size_t length)
{
    connection_t *data = (connection_t*)parser->data;
    if(data == NULL || at == NULL)
        return -1;
    http_headers_t *headers = &data->http->data.headers;
    http_body_t *body = &data->http->data.body;

    int rv = 0;
    int fd = data->fd;
    int slot = data->slot;
    SSL *ssl = data->ssl;
    worker_t *work = container_of((void*)(data-fd), worker_t, conn);
    config_t *conf = &work->mast->conf;

    if((int64_t)body->content_length <= 0)      //chunked编码
    {
        memcpy(body->val + body->len, at, length);
        body->len += length;
    }
    else                                        //普通编码
    {
        if(headers->type == HTTP_REQUEST)
        {
            rv = tcp_send(fd, (char*)at, length);
            if(rv != length)
            {
                log_err("%s tcp send data to backend \"%s:%hu\" failed - %d: %s", conf->ctrl[slot].serverName, data->ip, data->port, errno, strerror(errno));
                return -1;
            }
            log_debug("2, %s tcp send data to backend \"%s:%hu\" succeed - %d: %s", conf->ctrl[slot].serverName, data->ip, data->port, (int)length, at);
        }
        else
        {
            rv = ssl_write(ssl, (char*)at, length);
            if(rv != length)
            {
                log_err("%s ssl write data to frontend \"%s:%hu\" failed - %d: %s", conf->ctrl[slot].serverName, data->ip, data->port, errno, strerror(errno));
                return -1;
            }
            log_debug("4, %s ssl write data to frontend \"%s:%hu\" succeed - %d: %s", conf->ctrl[slot].serverName, data->ip, data->port, (int)length, at);
        }
    }

    log_debug("Body value - %d: %.*s", (int)length, (int)length, at);

    return 0;
}

int on_message_complete(http_parser *parser)
{
    connection_t *data = (connection_t*)parser->data;
    if(data == NULL)
        return -1;

    http_body_t *body = &data->http->data.body;
    if((int64_t)body->content_length > 0)
    {
        body->content_length = 0;
        body->val = NULL;
        body->len = 0;
    }

    http_parser_init(parser, HTTP_BOTH);
    parser->data = (void*)data;

    log_debug("***MESSAGE COMPLETE***");
    return 0;
}

int on_chunk_header(http_parser *parser)
{
    connection_t *data = (connection_t*)parser->data;
    if(data == NULL)
        return -1;

    http_body_t *body = &data->http->data.body;
    if(body)
    {
        body->content_length = 0;
        body->val = (unsigned char*)malloc(parser->content_length+12);
        if(body->val == NULL)
            return -1;
        memset(body->val, 0, parser->content_length+12);
        body->len = 0;

        if(parser->content_length == 0)
        {
            body->len = 1;
            *body->val = 0x30;
        }
        else
        {
            body->len += hex2ascii(parser->content_length, body->val + body->len);
        }
        body->len += sprintf((char*)(body->val + body->len), "\r\n");
    }

    log_debug("***CHUNK HEADER***");
    return 0;
}

int on_chunk_complete(http_parser *parser)
{
    connection_t *data = (connection_t*)parser->data;
    if(data == NULL)
        return -1;
    http_headers_t *headers = &data->http->data.headers;
    http_body_t *body = &data->http->data.body;

    int rv = 0;
    int fd = data->fd;
    int slot = data->slot;
    SSL *ssl = data->ssl;
    worker_t *work = container_of((void*)(data-fd), worker_t, conn);
    config_t *conf = &work->mast->conf;

    body->len += sprintf((char*)(body->val + body->len), "\r\n");
    if(headers->type == HTTP_REQUEST)
    {
        rv = tcp_send(fd, (char*)body->val, body->len);
        if(rv != body->len)
        {
            log_err("%s tcp send data to backend \"%s:%hu\" failed - %d: %s", conf->ctrl[slot].serverName, data->ip, data->port, errno, strerror(errno));
            return -1;
        }
        log_debug("2, %s tcp send data to backend \"%s:%hu\" succeed - %llu: %s", conf->ctrl[slot].serverName, data->ip, data->port, body->len, body->val);
    }
    else
    {
        rv = ssl_write(ssl, (char*)body->val, body->len);
        if(rv != body->len)
        {
            log_err("%s ssl write data to frontend \"%s:%hu\" failed - %d: %s", conf->ctrl[slot].serverName, data->ip, data->port, errno, strerror(errno));
            return -1;
        }
        log_debug("4, %s ssl write data to frontend \"%s:%hu\" succeed - %llu: %s", conf->ctrl[slot].serverName, data->ip, data->port, body->len, body->val);
    }

    if(body)
    {
        body->content_length = 0;
        if(body->val)
        {
            free(body->val);
            body->val = NULL;
        }
        body->len = 0;
    }

    log_debug("***CHUNK COMPLETE***");
    return 0;
}
