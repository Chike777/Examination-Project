#include <Arduino.h>
#include <mbedtls/md.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/aes.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

#define LED_DEBUG 32
#define SESSION_CLOSE 0xFF

typedef enum
{
    SESSION_OKAY,
    SESSION_ERROR,
    SESSION_TOGGLE_LED,
    SESSION_TEMPERATURE
} request_t;
enum
{
    STATUS_OKAY,
    STATUS_ERROR,
    STATUS_EXPIRED,
    STATUS_HASH_ERROR,
    STATUS_BAD_REQUEST,
    STATUS_INVALID_SESSION,
};

static uint32_t prev_millis;
constexpr int AES_SIZE{32};
constexpr int DER_SIZE{294};
constexpr int RSA_SIZE{256};
constexpr int HASH_SIZE{32};
constexpr int EXPONENT{65537};
constexpr int AES_BLOCK_SIZE{16};

// Contexts for cryptographic operations
static mbedtls_aes_context aes_ctx;
static mbedtls_md_context_t hmac_ctx;
static mbedtls_pk_context client_ctx;
static mbedtls_pk_context server_ctx;
static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context ctr_drbg;

// Session and cryptographic variables
static uint64_t session_id{0};
static uint8_t aes_key[AES_SIZE]{0};
static uint8_t enc_iv[AES_BLOCK_SIZE]{0};
static uint8_t dec_iv[AES_BLOCK_SIZE]{0};
static const uint8_t hmac_hash[HASH_SIZE] = {0x29, 0x49, 0xde, 0xc2, 0x3e, 0x1e, 0x34, 0xb5, 0x2d, 0x22, 0xb5,
                                             0xba, 0x4c, 0x34, 0x23, 0x3a, 0x9d, 0x3f, 0xe2, 0x97, 0x14, 0xbe,
                                             0x24, 0x62, 0x81, 0x0c, 0x86, 0xb1, 0xf6, 0x92, 0x54, 0xd6};

// Function prototypes
static bool tog_led();
static void log_error();
bool session_response(const uint8_t *res, size_t size);

// Function to receive data from the client with HMAC verification
static size_t serverSend(uint8_t *buffer, size_t blen)
{
    while (0 == Serial.available())
    {
        ;
    }

    size_t length = Serial.readBytes(buffer, blen);
    if (length > HASH_SIZE)
    {
        length -= HASH_SIZE;
        uint8_t hmac[HASH_SIZE]{0};
        mbedtls_md_hmac_starts(&hmac_ctx, hmac_hash, HASH_SIZE);
        mbedtls_md_hmac_update(&hmac_ctx, buffer, length);
        mbedtls_md_hmac_finish(&hmac_ctx, hmac);

        // Verify HMAC
        if (0 != memcmp(hmac, buffer + length, HASH_SIZE))
        {
            length = 0;
        }
    }
    else
    {
        length = 0;
    }

    return length;
}

// Function to send data to the client with HMAC
static bool client_write(uint8_t *buffer, size_t dlen)
{
    bool status{false};

    mbedtls_md_hmac_starts(&hmac_ctx, hmac_hash, HASH_SIZE);
    mbedtls_md_hmac_update(&hmac_ctx, buffer, dlen);
    mbedtls_md_hmac_finish(&hmac_ctx, buffer + dlen);
    dlen += HASH_SIZE;

    if (dlen == Serial.write(buffer, dlen)) // Send data over serial
    {
        Serial.flush();
        status = true;
    }

    return status;
}

// Function to exchange public keys with the client
static bool exchange_public_keys(uint8_t *buffer)
{
    session_id = 0;
    bool status = true;
    size_t olen, length;

    mbedtls_pk_init(&client_ctx); // Initialize client RSA context

    uint8_t cipher[3 * RSA_SIZE + HASH_SIZE] = {0};

    // Parse client's public key
    if (0 != mbedtls_pk_parse_public_key(&client_ctx, buffer, DER_SIZE))
    {
        status = false;
    }
    // Ensure the key is RSA
    if (MBEDTLS_PK_RSA != mbedtls_pk_get_type(&client_ctx))
    {
        status = false;
    }

    // Write server's public key in DER format
    if (DER_SIZE != mbedtls_pk_write_pubkey_der(&server_ctx, buffer, DER_SIZE))
    {
        status = false;
    }
    // Encrypt and send the server's public key
    if (0 != mbedtls_pk_encrypt(&client_ctx, buffer, DER_SIZE / 2, cipher,
                                &olen, RSA_SIZE, mbedtls_ctr_drbg_random, &ctr_drbg))
    {
        status = false;
    }

    if (0 != mbedtls_pk_encrypt(&client_ctx, buffer + DER_SIZE / 2, DER_SIZE / 2,
                                cipher + RSA_SIZE, &olen, RSA_SIZE, mbedtls_ctr_drbg_random, &ctr_drbg))
    {
        status = false;
    }

    length = 2 * RSA_SIZE;

    if (!client_write(cipher, length)) // Send encrypted public key
    {
        status = false;
    }

    // Receive and decrypt client's response
    length = serverSend(cipher, sizeof(cipher));

    if (!length == 3 * RSA_SIZE)
    {
        status = false;
    }

    if (0 != mbedtls_pk_decrypt(&server_ctx, cipher, RSA_SIZE, buffer, &olen, RSA_SIZE,
                                mbedtls_ctr_drbg_random, &ctr_drbg))
    {
        status = false;
    }

    length = olen;

    if (0 != mbedtls_pk_decrypt(&server_ctx, cipher + RSA_SIZE, RSA_SIZE, buffer + length,
                                &olen, RSA_SIZE, mbedtls_ctr_drbg_random, &ctr_drbg))
    {
        status = false;
    }

    length += olen;

    if (0 != mbedtls_pk_decrypt(&server_ctx, cipher + 2 * RSA_SIZE, RSA_SIZE, buffer + length,
                                &olen, RSA_SIZE, mbedtls_ctr_drbg_random, &ctr_drbg))
    {
        status = false;
    }

    length += olen;

    if (length != (DER_SIZE + RSA_SIZE))
    {
        status = false;
    }

    mbedtls_pk_init(&client_ctx);

    // Parse client's public key again
    if (0 != mbedtls_pk_parse_public_key(&client_ctx, buffer, DER_SIZE))
    {
        status = false;
    }

    // Ensure the key is RSA
    if (MBEDTLS_PK_RSA != mbedtls_pk_get_type(&client_ctx))
    {
        status = false;
    }
    // Verify client's signature
    if (0 != mbedtls_pk_verify(&client_ctx, MBEDTLS_MD_SHA256, hmac_hash, HASH_SIZE, buffer + DER_SIZE, RSA_SIZE))
    {
        status = false;
    }

    strcpy((char *)buffer, "OKAY");

    // Encrypt and send success message
    if (0 != mbedtls_pk_encrypt(&client_ctx, buffer, strlen((const char *)buffer),
                                cipher, &olen, RSA_SIZE, mbedtls_ctr_drbg_random, &ctr_drbg))
    {
        status = false;
    }

    length = RSA_SIZE;

    if (!client_write(cipher, length))
    {
        status = false;
    }

    return status;
}

// Function to establish a session with the client
static bool establish_session(uint8_t *buffer)
{
    session_id = 0;
    bool status = true;
    size_t olen, length;

    uint8_t cipher[RSA_SIZE]{0};

    // Decrypt client's session request
    if (0 != mbedtls_pk_decrypt(&server_ctx, buffer, RSA_SIZE, cipher, &olen,
                                RSA_SIZE, mbedtls_ctr_drbg_random, &ctr_drbg))
    {
        status = false;
    }

    length = olen;

    if (0 != mbedtls_pk_decrypt(&server_ctx, buffer + RSA_SIZE, RSA_SIZE, cipher + length,
                                &olen, RSA_SIZE, mbedtls_ctr_drbg_random, &ctr_drbg))
    {
        status = false;
    }

    length += olen;

    if (length != RSA_SIZE)
    {
        status = false;
    }

    // Verify client's signature
    if (0 != mbedtls_pk_verify(&client_ctx, MBEDTLS_MD_SHA256, hmac_hash, HASH_SIZE, cipher, RSA_SIZE))
    {
        status = false;
    }

    // Generate session ID and AES key
    uint8_t *ptr{(uint8_t *)&session_id};

    if (ptr != nullptr)
    {
        for (size_t i = 0; i < sizeof(session_id); i++)
        {
            ptr[i] = random(1, 0x100);
        }

        for (size_t i = 0; i < sizeof(enc_iv); i++)
        {
            enc_iv[i] = random(0x100);
        }
    }
    else
    {
        status = false;
    }

    memcpy(dec_iv, enc_iv, sizeof(dec_iv)); // Copy IV for decryption

    for (size_t i = 0; i < sizeof(aes_key); i++)
    {
        aes_key[i] = random(0x100);
    }

    // Set AES key for encryption
    if (0 != mbedtls_aes_setkey_enc(&aes_ctx, aes_key, sizeof(aes_key) * CHAR_BIT))
    {
        status = false;
    }

    // Prepare session data
    memcpy(buffer, &session_id, sizeof(session_id));

    length = sizeof(session_id);

    memcpy(buffer + length, enc_iv, sizeof(enc_iv));

    length += sizeof(enc_iv);

    memcpy(buffer + length, aes_key, sizeof(aes_key));

    length += sizeof(aes_key);

    // Encrypt and send session data
    if (0 != mbedtls_pk_encrypt(&client_ctx, buffer, length, cipher, &olen,
                                RSA_SIZE, mbedtls_ctr_drbg_random, &ctr_drbg))
    {
        status = false;
    }

    length = RSA_SIZE;

    if (client_write(cipher, length) == 0)
    {
        status = false;
    }

    return status;
}

// Setup function for initializing hardware and cryptographic contexts
void setup()
{
    Serial.begin(115200); // Initialize serial communicatio

    pinMode(LED_DEBUG, OUTPUT); // Set LED pin as output
    // HMAC-SHA256
    mbedtls_md_init(&hmac_ctx);
    assert(0 == mbedtls_md_setup(&hmac_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1));

    // Initialize AES context
    mbedtls_aes_init(&aes_ctx);

    // Initialize entropy and random number generator
    uint8_t initial[AES_SIZE]{0};
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    for (size_t i = 0; i < sizeof(initial); i++)
    {
        initial[i] = random(0x100);
    }
    assert(0 == mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, initial, sizeof(initial)));

    // Initialize RSA context and generate server's RSA key pair
    mbedtls_pk_init(&server_ctx);
    assert(0 == mbedtls_pk_setup(&server_ctx, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)));
    assert(0 == mbedtls_rsa_gen_key(mbedtls_pk_rsa(server_ctx), mbedtls_ctr_drbg_random,
                                    &ctr_drbg, RSA_SIZE * CHAR_BIT, EXPONENT));
}

// Loop for handling client requests
void loop()
{
    uint8_t response = STATUS_OKAY;
    uint8_t buffer[DER_SIZE + RSA_SIZE] = {0};
    size_t length = serverSend(buffer, sizeof(buffer)); // Receive data from client

    if (length == DER_SIZE)
    { // Exchange public keys
        if (!exchange_public_keys(buffer))
        {
            log_error();
        }
    }
    else if (length == 2 * RSA_SIZE)
    {
        if (!establish_session(buffer))
        {
            log_error(); // Log error if key exchange fails
        }
    }
    else if (length == AES_BLOCK_SIZE)
    { // Handle session requests
        if (session_id != 0)
        {

            uint8_t cipher[AES_BLOCK_SIZE]{0};
            // Decrypt client's request
            if (0 == mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_DECRYPT, length, dec_iv, buffer, cipher))
            {
                if (cipher[AES_BLOCK_SIZE - 1] == 9) // Check padding
                {
                    if (cipher[0] == 0x01) // Get temperature
                    {
                        if (0 == memcmp(&session_id, &cipher[1], sizeof(session_id)))
                        {
                            buffer[0] = 0x10;                                        // OKAY
                            sprintf((char *)&buffer[1], "%2.2f", temperatureRead()); // Read temperature
                        }
                    }
                    else if (cipher[0] == 0x02) // Toggel led
                    {
                        if (0 == memcmp(&session_id, &cipher[1], sizeof(session_id)))
                        {
                            buffer[0] = 0x10; // OKAY

                            sprintf((char *)&buffer[1], "%x", (tog_led()) ? 0x10684 : 0x10254);
                        }
                    }
                }
                else
                {
                    //
                }
                length = AES_BLOCK_SIZE;

                // Encrypt and send response
                if (0 == mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_ENCRYPT, length, enc_iv, buffer, cipher))
                {
                    if (!client_write(cipher, length))
                    {
                        log_error(); // Log error if sending fails
                    }
                }
                else
                {
                    log_error(); // Log error if encryption fail
                }
            }
        }
        else
        {
            ;
        }
    }

    else
    {
        log_error(); // Log error for invalid request
    }
}

// Function to toggle the debug LED
static bool tog_led()
{
    static bool state = false;
    digitalWrite(LED_DEBUG, state = !state);
    return state;
}

// Function to log an error
static void log_error()
{
    uint8_t log_buff[5] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    client_write(log_buff, DER_SIZE + RSA_SIZE);
}