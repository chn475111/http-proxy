#ifndef __HTTP_HANDLER_H__
#define __HTTP_HANDLER_H__

#include "http_parser.h"

#define MAX_BUFFER_SIZE 4096

typedef struct http_header_s
{
    int length;
    char buffer[MAX_BUFFER_SIZE];
}http_header_t;

typedef struct http_head_s
{
    http_header_t url;
    http_header_t status;
}http_head_t;

typedef struct http_body_s
{
}http_body_t;

typedef struct http_data_s
{
    http_head_t head;
    http_body_t body;
}http_data_t;

typedef struct http_s
{
    http_parser_settings settings;      //HTTP回调函数
    http_parser parser;                 //HTTP解析句柄
    http_data_t data;                   //HTTP数据内容
}http_t;

http_t *http_new(void *data);

int http_exec(http_t *h, const char *buf, int len);

void http_delete(http_t *h);

int on_message_begin(http_parser *parser);

int on_url(http_parser *parser, const char *at, size_t length);

int on_status(http_parser *parser, const char *at, size_t length);

int on_header_field(http_parser *parser, const char *at, size_t length);

int on_header_value(http_parser *parser, const char *at, size_t length);

int on_headers_complete(http_parser *parser);

int on_body(http_parser *parser, const char *at, size_t length);

int on_message_complete(http_parser *parser);

int on_chunk_header(http_parser *parser);

int on_chunk_complete(http_parser *parser);

#endif
