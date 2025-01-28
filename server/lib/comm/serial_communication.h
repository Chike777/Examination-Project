#ifndef SERIAL_COMMUNICATION_H
#define SERIAL_COMMUNICATION_H

#include <Arduino.h>

bool initialize_serial(void);
bool send_data(const uint8_t *data, size_t dlen);
size_t receive_data(uint8_t *buf, size_t blen);
void close_serial();

#endif // SERIAL_COMMUNICATION_H
