#ifndef __HTTP_HANDLER_H__
#define __HTTP_HANDLER_H__

#include "http_parser.h"

#define MAX_FIELD_SIZE 256
#define MAX_VALUE_SIZE 4096
#define MAX_HEADER_COUNT 256

typedef struct field_s
{
    int len;
    char val[MAX_FIELD_SIZE];
}field_t;

typedef struct value_s
{
    int len;
    char val[MAX_VALUE_SIZE];
}value_t;

typedef struct http_header_s
{
    field_t field;
    value_t value;
}http_header_t;

typedef struct http_headers_s
{
    unsigned int type;                  //HTTP请求/响应类型
    union{
        struct
        {
            unsigned int method;        //HTTP请求方法
            value_t url;                //HTTP请求路径
        }request;
        struct
        {
            unsigned int code;          //HTTP响应状态码
            value_t status;             //HTTP响应状态
        }response;
    }r;
    unsigned short major;               //HTTP主版本号
    unsigned short minor;               //HTTP次版本号
    int count;
    http_header_t header[MAX_HEADER_COUNT];
}http_headers_t;

typedef struct http_body_s
{
    unsigned long long content_length;
    unsigned long long len;
    unsigned char *val;
}http_body_t;

typedef struct http_data_s
{
    http_headers_t headers;
    http_body_t body;
}http_data_t;

typedef struct http_s
{
    http_parser_settings settings;      //HTTP回调函数
    http_parser parser;                 //HTTP解析句柄
    http_data_t data;                   //HTTP数据内容
}http_t;

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
