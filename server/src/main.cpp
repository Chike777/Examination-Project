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

static mbedtls_aes_context aes_ctx;
static mbedtls_md_context_t hmac_ctx;
static mbedtls_pk_context client_ctx;
static mbedtls_pk_context server_ctx;
static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context ctr_drbg;

static uint64_t session_id{0};
static uint8_t aes_key[AES_SIZE]{0};
static uint8_t enc_iv[AES_BLOCK_SIZE]{0};
static uint8_t dec_iv[AES_BLOCK_SIZE]{0};
static const uint8_t hmac_hash[HASH_SIZE] = {0x29, 0x49, 0xde, 0xc2, 0x3e, 0x1e, 0x34, 0xb5, 0x2d, 0x22, 0xb5,
                                             0xba, 0x4c, 0x34, 0x23, 0x3a, 0x9d, 0x3f, 0xe2, 0x97, 0x14, 0xbe,
                                             0x24, 0x62, 0x81, 0x0c, 0x86, 0xb1, 0xf6, 0x92, 0x54, 0xd6};

static bool tog_led();
static void log_error();
bool session_response(const uint8_t *res, size_t size);

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

static bool client_write(uint8_t *buffer, size_t dlen)
{
    bool status{false};

    mbedtls_md_hmac_starts(&hmac_ctx, hmac_hash, HASH_SIZE);
    mbedtls_md_hmac_update(&hmac_ctx, buffer, dlen);
    mbedtls_md_hmac_finish(&hmac_ctx, buffer + dlen);
    dlen += HASH_SIZE;

    if (dlen == Serial.write(buffer, dlen))
    {
        Serial.flush();
        status = true;
    }

    return status;
}

static bool exchange_public_keys(uint8_t *buffer)
{
    session_id = 0;
    bool status = true;
    size_t olen, length;

    mbedtls_pk_init(&client_ctx);

    uint8_t cipher[3 * RSA_SIZE + HASH_SIZE] = {0};

    if (0 != mbedtls_pk_parse_public_key(&client_ctx, buffer, DER_SIZE))
    {
        status = false;
    }

    if (MBEDTLS_PK_RSA != mbedtls_pk_get_type(&client_ctx))
    {
        status = false;
    }

    if (DER_SIZE != mbedtls_pk_write_pubkey_der(&server_ctx, buffer, DER_SIZE))
    {
        status = false;
    }

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

    if (!client_write(cipher, length))
    {
        status = false;
    }

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

    if (0 != mbedtls_pk_parse_public_key(&client_ctx, buffer, DER_SIZE))
    {
        status = false;
    }

    if (MBEDTLS_PK_RSA != mbedtls_pk_get_type(&client_ctx))
    {
        status = false;
    }

    if (0 != mbedtls_pk_verify(&client_ctx, MBEDTLS_MD_SHA256, hmac_hash, HASH_SIZE, buffer + DER_SIZE, RSA_SIZE))
    {
        status = false;
    }

    strcpy((char *)buffer, "OKAY");

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

static bool establish_session(uint8_t *buffer)
{
    session_id = 0;
    bool status = true;
    size_t olen, length;

    uint8_t cipher[RSA_SIZE]{0};

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

    if (0 != mbedtls_pk_verify(&client_ctx, MBEDTLS_MD_SHA256, hmac_hash, HASH_SIZE, cipher, RSA_SIZE))
    {
        status = false;
    }

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

    memcpy(dec_iv, enc_iv, sizeof(dec_iv));

    for (size_t i = 0; i < sizeof(aes_key); i++)
    {
        aes_key[i] = random(0x100);
    }

    if (0 != mbedtls_aes_setkey_enc(&aes_ctx, aes_key, sizeof(aes_key) * CHAR_BIT))
    {
        status = false;
    }

    memcpy(buffer, &session_id, sizeof(session_id));

    length = sizeof(session_id);

    memcpy(buffer + length, enc_iv, sizeof(enc_iv));

    length += sizeof(enc_iv);

    memcpy(buffer + length, aes_key, sizeof(aes_key));

    length += sizeof(aes_key);

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

void setup()
{
    Serial.begin(115200);

    pinMode(LED_DEBUG, OUTPUT);
    // HMAC-SHA256
    mbedtls_md_init(&hmac_ctx);
    assert(0 == mbedtls_md_setup(&hmac_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1));

    // AES-256
    mbedtls_aes_init(&aes_ctx);

    uint8_t initial[AES_SIZE]{0};
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    for (size_t i = 0; i < sizeof(initial); i++)
    {
        initial[i] = random(0x100);
    }
    assert(0 == mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, initial, sizeof(initial)));

    // RSA-2048
    mbedtls_pk_init(&server_ctx);
    assert(0 == mbedtls_pk_setup(&server_ctx, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)));
    assert(0 == mbedtls_rsa_gen_key(mbedtls_pk_rsa(server_ctx), mbedtls_ctr_drbg_random,
                                    &ctr_drbg, RSA_SIZE * CHAR_BIT, EXPONENT));
}

void loop()
{
    uint8_t response = STATUS_OKAY;
    uint8_t buffer[DER_SIZE + RSA_SIZE] = {0};
    size_t length = serverSend(buffer, sizeof(buffer));

    if (length == DER_SIZE)
    {
        if (!exchange_public_keys(buffer))
        {
            log_error();
        }
    }
    else if (length == 2 * RSA_SIZE)
    {
        if (!establish_session(buffer))
        {
            log_error();
        }
    }
    else if (length == AES_BLOCK_SIZE)
    {
        if (session_id != 0)
        {

            uint8_t cipher[AES_BLOCK_SIZE]{0};
            if (0 == mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_DECRYPT, length, dec_iv, buffer, cipher))
            {
                if (cipher[AES_BLOCK_SIZE - 1] == 9)
                {
                    if (cipher[0] == 0x01) // Get temperature
                    {
                        if (0 == memcmp(&session_id, &cipher[1], sizeof(session_id)))
                        {
                            buffer[0] = 0x10; // OKAY
                            sprintf((char *)&buffer[1], "%2.2f", temperatureRead());
                        }
                    }
                    else if (cipher[0] == 0x02) // Toggel led
                    {
                        if (0 == memcmp(&session_id, &cipher[1], sizeof(session_id)))
                        {
                            buffer[0] = 0x10; // OKAY

                            sprintf((char *)&buffer[1], "%x", (tog_led()) ? 0x11111 : 0x10101);
                        }
                    }
                }
                else
                {
                    //
                }
                length = AES_BLOCK_SIZE;

                if (0 == mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_ENCRYPT, length, enc_iv, buffer, cipher))
                {
                    if (!client_write(cipher, length))
                    {
                        log_error();
                    }
                }
                else
                {
                    log_error();
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
        log_error();
    }
}

static bool tog_led()
{
    static bool state = false;
    digitalWrite(LED_DEBUG, state = !state);
    return state;
}

static void log_error()
{
    uint8_t log_buff[5] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    client_write(log_buff, DER_SIZE + RSA_SIZE);
}