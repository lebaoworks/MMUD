#pragma once

#include <stdlib.h>
#include <stdint.h>
#include "library/net.h"

#define AS_PORT 4445
#define TGS_PORT 4446
#define SS_PORT 4447

#define TGS_KEY "\x3b\x81\x12\xa3\x05\x55\xa2\x04\xf9\x8c\xab\x67\x2c\x90\x0f\x8e"
#define SS_KEY  "\x5d\x82\x24\x9c\x91\x0f\xeb\x34\x0f\xfa\xd6\xc3\x1d\xda\x65\xa6"

int user_num = 7;
uint32_t user_id[] = {0, 1, 2, 3, 4, 5, 6};
char*   user_pass[] = {"0", "1", "2", "3", "4", "5", "6"};

typedef uint32_t ID;
typedef uint8_t Key[16];

typedef struct _CLIENT_INFO
{
    ID id;
    struct in_addr sin_addr;
    struct _validity
    {
        time_t timestamp;
        uint16_t duration;
    } validity;
} CLIENT_INFO;

typedef struct _AS_REQUEST
{
    ID id;
} AS_REQUEST;

typedef struct _AS_RESPONSE
{
    struct _MESSAGE_A
    {
        Key session_key;
    } message_a;
    struct _MESSAGE_B
    {
        Key session_key;
        CLIENT_INFO client_info;
    } message_b;
} AS_RESPONSE;

typedef struct _TGS_REQUEST
{
    struct _MESSAGE_C
    {
        struct _MESSAGE_B message;
    } message_c;
    ID service_id;
    struct _MESSAGE_D
    {
        ID id;
        time_t timestamp;
    } message_d;
} TGS_REQUEST;

typedef struct _TGS_RESPONSE
{
    struct _MESSAGE_E
    {
        Key session_key;
        CLIENT_INFO client_info;
    } message_e;
    struct _MESSAGE_F
    {
        Key session_key;
    } message_f;
} TGS_RESPONSE;

typedef struct _SS_REQUEST
{
    struct _MESSAGE_E message_e;
    ID service_id;
    struct _MESSAGE_G
    {
        ID id;
        time_t timestamp;
    } message_g;
} SS_REQUEST;

typedef struct _SS_RESPONSE
{
    time_t timestamp;
} SS_RESPONSE;

#define SERVICE_A 1
#define SERVICE_B 2
#define SERVICE_C 3
