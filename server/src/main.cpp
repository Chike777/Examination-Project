#include <Arduino.h>

#define LED_PIN 21
#define RELAY_PIN 32

// Variable to keep track of LED state
int ledState = LOW;

void toggle_led()
{
    ledState = !ledState;
    digitalWrite(LED_PIN, ledState);
}

void setup()
{
    pinMode(LED_PIN, OUTPUT);
    pinMode(RELAY_PIN, OUTPUT);
    digitalWrite(LED_PIN, LOW);
    digitalWrite(RELAY_PIN, LOW);
    Serial.begin(115200);
}

void loop()
{
    if (Serial.available() > 0)
    {
        String command = Serial.readStringUntil('\n');
        command.trim();

        if (command == "GET_TEMP")
        {
            // Simulate temperature reading
            float temperature = 65.0;
            Serial.println(temperature);
        }
        else if (command == "TOGGLE_RELAY")
        {
            // Toggle the relay
            digitalWrite(RELAY_PIN, !digitalRead(RELAY_PIN));
            Serial.println(digitalRead(RELAY_PIN) ? "ON" : "OFF");
        }
        else
        {
            Serial.println("ERROR: Unknown command");
        }
    }
}