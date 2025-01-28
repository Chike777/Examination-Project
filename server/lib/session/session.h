#ifndef SESSION_H
#define SESSION_H

#include <stdint.h>
#include <stddef.h>

enum
{
    SESSION_ERROR,
    SESSION_OKAY,
    SESSION_TEMPERATURE,
    SESSION_TOGGLE_LED,
};

typedef struct response_t
{
    uint8_t len;
    uint8_t data[8];
} response_t;

void session_init(void);

int session_request(void);

int session_response(response_t *resp);

#endif
