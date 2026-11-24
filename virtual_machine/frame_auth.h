#ifndef CERISE_FRAME_AUTH_H
#define CERISE_FRAME_AUTH_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

enum { FA_OK = 0, FA_ERR_ARGS, FA_ERR_FORMAT, FA_ERR_MAC, FA_ERR_CRYPTO, FA_ERR_CAPACITY };

enum {
    FA_SESSION_KEY_BYTES = 16,
    FA_SESSION_KEY_HEX_LEN = 32,
    FA_ENC_KEY_BYTES = 16,
    FA_MAC_KEY_BYTES = 32,
    FA_COUNTER_BYTES = 8,
    FA_IV_BYTES = 16,
    FA_TAG_BYTES = 16,
    FA_BLOCK_BYTES = 16,
    FA_PREFIX_BYTES = 2,
    FA_MAX_PLAIN_BYTES = 8192,
    FA_MAX_BODY_BYTES = 65535,
    FA_HMAC_FULL_BYTES = 32,
    FA_DMI_HEADER_BYTES = 4,
    FA_SMBIOS_END_OF_TABLE_TYPE = 127,
    FA_BITS_PER_BYTE = 8,
    FA_HEX_NIBBLE_BITS = 4
};

typedef struct {
    unsigned char enc_key[16];
    unsigned char mac_key[32];
} fa_keys;

static inline int fa_hex_digit(char symbol)
{
    if (symbol >= '0' && symbol <= '9') return symbol - '0';
    if (symbol >= 'a' && symbol <= 'f') return symbol - 'a' + 10;
    if (symbol >= 'A' && symbol <= 'F') return symbol - 'A' + 10;
    return -1;
}

static inline int fa_decode_session_key(const char *hex, unsigned char *out)
{
    if (strlen(hex) != FA_SESSION_KEY_HEX_LEN) return FA_ERR_ARGS;
    for (size_t index = 0; index < FA_SESSION_KEY_BYTES; index++) {
        int high = fa_hex_digit(hex[index * 2]);
        int low = fa_hex_digit(hex[index * 2 + 1]);
        if (high < 0 || low < 0) return FA_ERR_ARGS;
        out[index] = (unsigned char)((high << FA_HEX_NIBBLE_BITS) | low);
    }
    return FA_OK;
}

static inline int fa_hmac(const unsigned char *key, size_t key_len,
                   const unsigned char *part_a, size_t len_a,
                   const unsigned char *part_b, size_t len_b,
                   const unsigned char *part_c, size_t len_c,
                   unsigned char *digest_out)
{
    unsigned char joined[FA_COUNTER_BYTES + FA_IV_BYTES + FA_MAX_PLAIN_BYTES + FA_BLOCK_BYTES];
    unsigned int digest_len = 0;
    size_t total = len_a + len_b + len_c;
    if (total > sizeof(joined)) return FA_ERR_CAPACITY;
    if (len_a) memcpy(joined, part_a, len_a);
    if (len_b) memcpy(joined + len_a, part_b, len_b);
    if (len_c) memcpy(joined + len_a + len_b, part_c, len_c);
    if (!HMAC(EVP_sha256(), key, (int)key_len, joined, total, digest_out, &digest_len)) return FA_ERR_CRYPTO;
    OPENSSL_cleanse(joined, total);
    return digest_len == FA_HMAC_FULL_BYTES ? FA_OK : FA_ERR_CRYPTO;
}

static inline int fa_derive_keys(const char *session_key_hex, fa_keys *keys_out)
{
    static const unsigned char enc_label[] = "cerise-enc";
    static const unsigned char mac_label[] = "cerise-mac";
    unsigned char session_key[FA_SESSION_KEY_BYTES];
    unsigned char enc_full[FA_HMAC_FULL_BYTES];
    int status;
    if (!session_key_hex || !keys_out) return FA_ERR_ARGS;
    status = fa_decode_session_key(session_key_hex, session_key);
    if (status != FA_OK) return status;
    status = fa_hmac(session_key, sizeof(session_key), enc_label, sizeof(enc_label) - 1, NULL, 0, NULL, 0, enc_full);
    if (status != FA_OK) return status;
    memcpy(keys_out->enc_key, enc_full, FA_ENC_KEY_BYTES);
    status = fa_hmac(session_key, sizeof(session_key), mac_label, sizeof(mac_label) - 1, NULL, 0, NULL, 0, keys_out->mac_key);
    OPENSSL_cleanse(session_key, sizeof(session_key));
    OPENSSL_cleanse(enc_full, sizeof(enc_full));
    return status;
}

static inline void fa_store_counter(uint64_t counter, unsigned char *out)
{
    for (int index = 0; index < FA_COUNTER_BYTES; index++)
        out[index] = (unsigned char)(counter >> (FA_BITS_PER_BYTE * (FA_COUNTER_BYTES - 1 - index)));
}

static inline uint64_t fa_load_counter(const unsigned char *in)
{
    uint64_t counter = 0;
    for (int index = 0; index < FA_COUNTER_BYTES; index++)
        counter = (counter << FA_BITS_PER_BYTE) | in[index];
    return counter;
}

static inline int fa_cipher(int encrypt, const unsigned char *key, const unsigned char *iv,
                     const unsigned char *input, size_t input_len,
                     unsigned char *output, size_t output_capacity, size_t *output_len)
{
    int written = 0;
    int finished = 0;
    int ok;
    EVP_CIPHER_CTX *context;
    if (input_len > (size_t)FA_MAX_BODY_BYTES || output_capacity < input_len + FA_BLOCK_BYTES) return FA_ERR_CAPACITY;
    context = EVP_CIPHER_CTX_new();
    if (!context) return FA_ERR_CRYPTO;
    ok = EVP_CipherInit_ex(context, EVP_aes_128_cbc(), NULL, key, iv, encrypt) == 1
        && EVP_CipherUpdate(context, output, &written, input, (int)input_len) == 1
        && EVP_CipherFinal_ex(context, output + written, &finished) == 1;
    EVP_CIPHER_CTX_free(context);
    if (!ok) return encrypt ? FA_ERR_CRYPTO : FA_ERR_FORMAT;
    *output_len = (size_t)(written + finished);
    return FA_OK;
}

static inline int fa_build_frame(const fa_keys *keys, uint64_t counter, const unsigned char *plain, size_t plain_len,
                          unsigned char *frame_out, size_t frame_capacity, size_t *frame_len_out)
{
    unsigned char cipher_buffer[FA_MAX_PLAIN_BYTES + FA_BLOCK_BYTES];
    unsigned char digest[FA_HMAC_FULL_BYTES];
    unsigned char *body;
    size_t cipher_len = 0;
    size_t body_len;
    int status;
    if (!keys || !frame_out || !frame_len_out || (!plain && plain_len > 0)) return FA_ERR_ARGS;
    if (plain_len > FA_MAX_PLAIN_BYTES) return FA_ERR_ARGS;
    body_len = FA_COUNTER_BYTES + FA_IV_BYTES + (plain_len / FA_BLOCK_BYTES + 1) * FA_BLOCK_BYTES + FA_TAG_BYTES;
    if (frame_capacity < FA_PREFIX_BYTES + body_len) return FA_ERR_CAPACITY;
    body = frame_out + FA_PREFIX_BYTES;
    fa_store_counter(counter, body);
    if (RAND_bytes(body + FA_COUNTER_BYTES, FA_IV_BYTES) != 1) return FA_ERR_CRYPTO;
    status = fa_cipher(1, keys->enc_key, body + FA_COUNTER_BYTES, plain, plain_len,
                       cipher_buffer, sizeof(cipher_buffer), &cipher_len);
    if (status != FA_OK) return status;
    if (cipher_len != body_len - FA_COUNTER_BYTES - FA_IV_BYTES - FA_TAG_BYTES) return FA_ERR_CRYPTO;
    memcpy(body + FA_COUNTER_BYTES + FA_IV_BYTES, cipher_buffer, cipher_len);
    status = fa_hmac(keys->mac_key, FA_MAC_KEY_BYTES, body, FA_COUNTER_BYTES + FA_IV_BYTES,
                     body + FA_COUNTER_BYTES + FA_IV_BYTES, cipher_len, NULL, 0, digest);
    if (status != FA_OK) return status;
    memcpy(body + FA_COUNTER_BYTES + FA_IV_BYTES + cipher_len, digest, FA_TAG_BYTES);
    frame_out[0] = (unsigned char)(body_len >> FA_BITS_PER_BYTE);
    frame_out[1] = (unsigned char)(body_len & 0xff);
    *frame_len_out = FA_PREFIX_BYTES + body_len;
    return FA_OK;
}

static inline int fa_open_body(const fa_keys *keys, const unsigned char *body, size_t body_len,
                        uint64_t *counter_out, unsigned char *plain_out, size_t plain_capacity, size_t *plain_len_out)
{
    const size_t overhead = FA_COUNTER_BYTES + FA_IV_BYTES + FA_TAG_BYTES;
    unsigned char digest[FA_HMAC_FULL_BYTES];
    unsigned char plain_buffer[FA_MAX_PLAIN_BYTES + FA_BLOCK_BYTES];
    const unsigned char *cipher;
    size_t cipher_len;
    size_t plain_len = 0;
    int status;
    if (!keys || !body || !counter_out || !plain_out || !plain_len_out) return FA_ERR_ARGS;
    if (body_len < overhead + FA_BLOCK_BYTES || body_len > FA_MAX_BODY_BYTES) return FA_ERR_FORMAT;
    cipher_len = body_len - overhead;
    if (cipher_len % FA_BLOCK_BYTES != 0 || cipher_len > FA_MAX_PLAIN_BYTES + FA_BLOCK_BYTES) return FA_ERR_FORMAT;
    cipher = body + FA_COUNTER_BYTES + FA_IV_BYTES;
    status = fa_hmac(keys->mac_key, FA_MAC_KEY_BYTES, body, FA_COUNTER_BYTES + FA_IV_BYTES, cipher, cipher_len, NULL, 0, digest);
    if (status != FA_OK) return status;
    if (CRYPTO_memcmp(digest, cipher + cipher_len, FA_TAG_BYTES) != 0) return FA_ERR_MAC;
    status = fa_cipher(0, keys->enc_key, body + FA_COUNTER_BYTES, cipher, cipher_len,
                       plain_buffer, sizeof(plain_buffer), &plain_len);
    if (status != FA_OK) return status;
    if (plain_len > plain_capacity) return FA_ERR_CAPACITY;
    memcpy(plain_out, plain_buffer, plain_len);
    *plain_len_out = plain_len;
    *counter_out = fa_load_counter(body);
    return FA_OK;
}

static inline int fa_copy_matching_value(const char *entry, size_t entry_len, const char *key_name,
                                  size_t key_len, char *value_out, size_t value_capacity)
{
    size_t value_len;
    if (entry_len <= key_len || memcmp(entry, key_name, key_len) != 0 || entry[key_len] != '=') return 0;
    value_len = entry_len - key_len - 1;
    if (value_len + 1 > value_capacity) return -1;
    memcpy(value_out, entry + key_len + 1, value_len);
    value_out[value_len] = '\0';
    return 1;
}

static inline int fa_parse_dmi_type11(const unsigned char *raw, size_t raw_len, const char *key_name,
                               char *value_out, size_t value_capacity)
{
    size_t offset;
    size_t key_len;
    if (!raw || !key_name || !value_out || value_capacity == 0) return FA_ERR_ARGS;
    key_len = strlen(key_name);
    if (key_len == 0 || raw_len < FA_DMI_HEADER_BYTES) return FA_ERR_FORMAT;
    offset = raw[1];
    if (offset < FA_DMI_HEADER_BYTES) return FA_ERR_FORMAT;
    while (offset < raw_len && raw[offset] != '\0') {
        const char *entry = (const char *)raw + offset;
        size_t entry_len = strnlen(entry, raw_len - offset);
        int match;
        if (offset + entry_len >= raw_len) return FA_ERR_FORMAT;
        match = fa_copy_matching_value(entry, entry_len, key_name, key_len, value_out, value_capacity);
        if (match < 0) return FA_ERR_CAPACITY;
        if (match > 0) return FA_OK;
        offset += entry_len + 1;
    }
    return FA_ERR_FORMAT;
}

static inline int fa_measure_structure(const unsigned char *table, size_t table_len, size_t start, size_t *structure_len_out)
{
    size_t offset;
    size_t formatted_len = table[start + 1];
    if (formatted_len < FA_DMI_HEADER_BYTES || formatted_len > table_len - start) return FA_ERR_FORMAT;
    offset = start + formatted_len;
    while (offset + 1 < table_len) {
        if (table[offset] == '\0' && table[offset + 1] == '\0') {
            *structure_len_out = offset + 2 - start;
            return FA_OK;
        }
        offset++;
    }
    return FA_ERR_FORMAT;
}

static inline int fa_find_smbios_structure(const unsigned char *table, size_t table_len, unsigned char wanted_type,
                                    const unsigned char **structure_out, size_t *structure_len_out)
{
    size_t offset = 0;
    if (!table || !structure_out || !structure_len_out) return FA_ERR_ARGS;
    while (table_len - offset >= FA_DMI_HEADER_BYTES) {
        size_t structure_len = 0;
        int status = fa_measure_structure(table, table_len, offset, &structure_len);
        if (status != FA_OK) return status;
        if (table[offset] == wanted_type) {
            *structure_out = table + offset;
            *structure_len_out = structure_len;
            return FA_OK;
        }
        if (table[offset] == FA_SMBIOS_END_OF_TABLE_TYPE) return FA_ERR_FORMAT;
        offset += structure_len;
    }
    return FA_ERR_FORMAT;
}

#endif
