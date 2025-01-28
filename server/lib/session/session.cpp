#include "session.h"
#include "serial_communication.h"
#include <Arduino.h>
#include <mbedtls/md.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/aes.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <assert.h>

#define DER_SIZE 294
#define RSA_SIZE 256
#define HASH_SIZE 32
#define EXPONENT 65537
#define AES_KEY_SIZE 32
#define AES_CIPHER_SIZE 16

#define SESSION_CLOSE 0xFF
#define SESSION_TIMEOUT 60000

typedef struct
{
    size_t length;
    uint8_t buffer[RSA_SIZE + DER_SIZE];
} message_t;

static mbedtls_aes_context aes_ctx;
static mbedtls_md_context_t hmac_ctx;
static mbedtls_pk_context client_ctx;
static mbedtls_pk_context server_ctx;
static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context ctr_drbg;

static uint64_t session_id{0};
static uint8_t aes_key[AES_KEY_SIZE]{0};
static uint8_t enc_iv[AES_CIPHER_SIZE]{0};
static uint8_t dec_iv[AES_CIPHER_SIZE]{0};
static const uint8_t hmac_hash[HASH_SIZE] = {0x29, 0x49, 0xde, 0xc2, 0x3e, 0x1e, 0x34, 0xb5, 0x2d, 0x22, 0xb5,
                                             0xba, 0x4c, 0x34, 0x23, 0x3a, 0x9d, 0x3f, 0xe2, 0x97, 0x14, 0xbe,
                                             0x24, 0x62, 0x81, 0x0c, 0x86, 0xb1, 0xf6, 0x92, 0x54, 0xd6};

static uint32_t prev_millis;

static size_t receive(uint8_t *buffer, size_t blen)
{
    size_t len = receive_data(buffer, blen);

    if (len > HASH_SIZE)
    {
        len -= HASH_SIZE;
        uint8_t hmac[HASH_SIZE]{0};

        mbedtls_md_hmac_starts(&hmac_ctx, hmac_hash, HASH_SIZE);
        mbedtls_md_hmac_update(&hmac_ctx, buffer, len);
        mbedtls_md_hmac_finish(&hmac_ctx, hmac);

        if (0 != memcmp(hmac, buffer + len, HASH_SIZE))
        {
            len = 0;
        }
    }

    return len;
}

static bool send(uint8_t *buffer, size_t size)
{
    mbedtls_md_hmac_starts(&hmac_ctx, hmac_hash, HASH_SIZE);
    mbedtls_md_hmac_update(&hmac_ctx, buffer, size);
    mbedtls_md_hmac_finish(&hmac_ctx, buffer + size);

    size += HASH_SIZE;

    return send_data(buffer, size);
}

static void exchange_public_keys(uint8_t *buffer)
{
    session_id = 0;

    size_t olen, length;

    mbedtls_pk_init(&client_ctx);

    uint8_t cipher[3 * RSA_SIZE + HASH_SIZE] = {0};

    assert(0 == mbedtls_pk_parse_public_key(&client_ctx, buffer, DER_SIZE));
    assert(MBEDTLS_PK_RSA == mbedtls_pk_get_type(&client_ctx));
    assert(DER_SIZE == mbedtls_pk_write_pubkey_der(&server_ctx, buffer, DER_SIZE));
    assert(0 == mbedtls_pk_encrypt(&client_ctx, buffer, DER_SIZE / 2, cipher,
                                   &olen, RSA_SIZE, mbedtls_ctr_drbg_random, &ctr_drbg));
    assert(0 == mbedtls_pk_encrypt(&client_ctx, buffer + DER_SIZE / 2, DER_SIZE / 2,
                                   cipher + RSA_SIZE, &olen, RSA_SIZE, mbedtls_ctr_drbg_random, &ctr_drbg));

    length = 2 * RSA_SIZE;

    assert(send(cipher, length));

    length = receive(cipher, sizeof(cipher));
    assert(length == 3 * RSA_SIZE);

    assert(0 == mbedtls_pk_decrypt(&server_ctx, cipher, RSA_SIZE, buffer, &olen, RSA_SIZE,
                                   mbedtls_ctr_drbg_random, &ctr_drbg));

    length = olen;

    assert(0 == mbedtls_pk_decrypt(&server_ctx, cipher + RSA_SIZE, RSA_SIZE, buffer + length,
                                   &olen, RSA_SIZE, mbedtls_ctr_drbg_random, &ctr_drbg));

    length += olen;

    assert(0 == mbedtls_pk_decrypt(&server_ctx, cipher + 2 * RSA_SIZE, RSA_SIZE, buffer + length,
                                   &olen, RSA_SIZE, mbedtls_ctr_drbg_random, &ctr_drbg));

    length += olen;

    assert(length == (DER_SIZE + RSA_SIZE));

    mbedtls_pk_init(&client_ctx);

    assert(0 == mbedtls_pk_parse_public_key(&client_ctx, buffer, DER_SIZE));
    assert(MBEDTLS_PK_RSA == mbedtls_pk_get_type(&client_ctx));
    assert(0 == mbedtls_pk_verify(&client_ctx, MBEDTLS_MD_SHA256, hmac_hash, HASH_SIZE, buffer + DER_SIZE, RSA_SIZE));

    strcpy((char *)buffer, "OKAY");

    assert(0 == mbedtls_pk_encrypt(&client_ctx, buffer, strlen((const char *)buffer),
                                   cipher, &olen, RSA_SIZE, mbedtls_ctr_drbg_random, &ctr_drbg));

    length = RSA_SIZE;

    assert(send(cipher, length));
}

static void establish_session(uint8_t *buffer)
{
    session_id = 0;

    size_t olen, length;

    uint8_t cipher[RSA_SIZE]{0};

    assert(0 == mbedtls_pk_decrypt(&server_ctx, buffer, RSA_SIZE, cipher, &olen,
                                   RSA_SIZE, mbedtls_ctr_drbg_random, &ctr_drbg));

    length = olen;

    assert(0 == mbedtls_pk_decrypt(&server_ctx, buffer + RSA_SIZE, RSA_SIZE, cipher + length,
                                   &olen, RSA_SIZE, mbedtls_ctr_drbg_random, &ctr_drbg));

    length += olen;

    assert(length == RSA_SIZE);

    assert(0 == mbedtls_pk_verify(&client_ctx, MBEDTLS_MD_SHA256, hmac_hash, HASH_SIZE, cipher, RSA_SIZE));

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
        assert(false);
    }

    memcpy(dec_iv, enc_iv, sizeof(dec_iv));

    for (size_t i = 0; i < sizeof(aes_key); i++)
    {
        aes_key[i] = random(0x100);
    }

    assert(0 == mbedtls_aes_setkey_enc(&aes_ctx, aes_key, sizeof(aes_key) * CHAR_BIT));

    memcpy(buffer, &session_id, sizeof(session_id));

    length = sizeof(session_id);

    memcpy(buffer + length, enc_iv, sizeof(enc_iv));

    length += sizeof(enc_iv);

    memcpy(buffer + length, aes_key, sizeof(aes_key));

    length += sizeof(aes_key);

    assert(0 == mbedtls_pk_encrypt(&client_ctx, buffer, length, cipher, &olen,
                                   RSA_SIZE, mbedtls_ctr_drbg_random, &ctr_drbg));

    length = RSA_SIZE;

    assert(send(cipher, length));
}

void session_init()
{
    initialize_serial();

    mbedtls_md_init(&hmac_ctx);
    assert(0 == mbedtls_md_setup(&hmac_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1));

    mbedtls_aes_init(&aes_ctx);

    uint8_t initial[AES_KEY_SIZE]{0};
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    for (size_t i = 0; i < sizeof(initial); i++)
    {
        initial[i] = random(0x100);
    }
    assert(0 == mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, initial, sizeof(initial)));

    mbedtls_pk_init(&server_ctx);

    assert(0 == mbedtls_pk_setup(&server_ctx, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)));
    assert(0 == mbedtls_rsa_gen_key(mbedtls_pk_rsa(server_ctx), mbedtls_ctr_drbg_random,
                                    &ctr_drbg, RSA_SIZE * CHAR_BIT, EXPONENT));
}

int session_request(void)
{
    message_t message{0};
    int status{SESSION_OKAY};

    message.length = receive(message.buffer, (RSA_SIZE + DER_SIZE));

    if (message.length == DER_SIZE)
    {
        exchange_public_keys(message.buffer);
    }
    else if (message.length == 2 * RSA_SIZE)
    {
        establish_session(message.buffer);
        prev_millis = millis();
    }
    else if (message.length == AES_CIPHER_SIZE)
    {
        if (session_id != 0)
        {
            uint8_t cipher[AES_CIPHER_SIZE]{0};

            if (0 != mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_DECRYPT, message.length, dec_iv, message.buffer, cipher))
            {
                assert(false);
            }
            if (cipher[AES_CIPHER_SIZE - 1] == 9)
            {
                status = cipher[0];
            }
        }
    }

    return status;
}

int session_response(response_t *resp)
{
    int status{SESSION_OKAY};

    uint8_t cipher[AES_CIPHER_SIZE + HASH_SIZE]{0};

    resp->len = AES_CIPHER_SIZE;

    if (0 == mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_ENCRYPT, resp->len, enc_iv, resp->data, cipher))
    {
        if (!send(cipher, resp->len))
        {
            status = SESSION_ERROR;
            assert(false);
        }
    }

    return status;
}
