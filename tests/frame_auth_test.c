#include <stdio.h>
#include <stdlib.h>
#include "frame_auth.h"

#define CHECK(condition) do { if (!(condition)) { fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #condition); exit(1); } } while (0)

static const char KEY_HEX[] = "00112233445566778899aabbccddeeff";
static const char OTHER_KEY_HEX[] = "ffeeddccbbaa99887766554433221100";
static const char MESSAGE[] = "{\"event\":\"exec\",\"pid\":42}";
enum { FRAME_CAPACITY = 9000, COUNTER_VALUE = 0x0102030405060708ULL };

static void test_round_trip(void)
{
    fa_keys keys;
    unsigned char frame[FRAME_CAPACITY], plain[FRAME_CAPACITY];
    size_t frame_len = 0, plain_len = 0;
    uint64_t counter = 0;
    CHECK(fa_derive_keys(KEY_HEX, &keys) == FA_OK);
    CHECK(fa_build_frame(&keys, COUNTER_VALUE, (const unsigned char *)MESSAGE, sizeof(MESSAGE) - 1, frame, sizeof(frame), &frame_len) == FA_OK);
    CHECK((size_t)((frame[0] << 8) | frame[1]) == frame_len - 2);
    CHECK(fa_open_body(&keys, frame + 2, frame_len - 2, &counter, plain, sizeof(plain), &plain_len) == FA_OK);
    CHECK(counter == COUNTER_VALUE);
    CHECK(plain_len == sizeof(MESSAGE) - 1 && memcmp(plain, MESSAGE, plain_len) == 0);
}

static void test_tamper(void)
{
    fa_keys keys;
    unsigned char frame[FRAME_CAPACITY], plain[FRAME_CAPACITY];
    size_t frame_len = 0, plain_len = 0;
    uint64_t counter = 0;
    CHECK(fa_derive_keys(KEY_HEX, &keys) == FA_OK);
    CHECK(fa_build_frame(&keys, 1, (const unsigned char *)MESSAGE, sizeof(MESSAGE) - 1, frame, sizeof(frame), &frame_len) == FA_OK);
    frame[2 + 8 + 16] ^= 1;
    CHECK(fa_open_body(&keys, frame + 2, frame_len - 2, &counter, plain, sizeof(plain), &plain_len) == FA_ERR_MAC);
    frame[2 + 8 + 16] ^= 1;
    frame[frame_len - 1] ^= 1;
    CHECK(fa_open_body(&keys, frame + 2, frame_len - 2, &counter, plain, sizeof(plain), &plain_len) == FA_ERR_MAC);
}

static void test_wrong_key_and_short(void)
{
    fa_keys keys, other;
    unsigned char frame[FRAME_CAPACITY], plain[FRAME_CAPACITY];
    size_t frame_len = 0, plain_len = 0;
    uint64_t counter = 0;
    CHECK(fa_derive_keys(KEY_HEX, &keys) == FA_OK);
    CHECK(fa_derive_keys(OTHER_KEY_HEX, &other) == FA_OK);
    CHECK(fa_build_frame(&keys, 1, (const unsigned char *)MESSAGE, sizeof(MESSAGE) - 1, frame, sizeof(frame), &frame_len) == FA_OK);
    CHECK(fa_open_body(&other, frame + 2, frame_len - 2, &counter, plain, sizeof(plain), &plain_len) == FA_ERR_MAC);
    CHECK(fa_open_body(&keys, frame + 2, 10, &counter, plain, sizeof(plain), &plain_len) == FA_ERR_FORMAT);
}

static void test_capacity(void)
{
    fa_keys keys;
    unsigned char frame[FRAME_CAPACITY], small[8], plain[FRAME_CAPACITY];
    size_t frame_len = 0, plain_len = 0;
    uint64_t counter = 0;
    CHECK(fa_derive_keys(KEY_HEX, &keys) == FA_OK);
    CHECK(fa_build_frame(&keys, 1, (const unsigned char *)MESSAGE, sizeof(MESSAGE) - 1, small, sizeof(small), &frame_len) == FA_ERR_CAPACITY);
    CHECK(fa_build_frame(&keys, 1, (const unsigned char *)MESSAGE, sizeof(MESSAGE) - 1, frame, sizeof(frame), &frame_len) == FA_OK);
    CHECK(fa_open_body(&keys, frame + 2, frame_len - 2, &counter, small, 4, &plain_len) == FA_ERR_CAPACITY);
    CHECK(fa_open_body(&keys, frame + 2, frame_len - 2, &counter, plain, sizeof(plain), &plain_len) == FA_OK);
}

static void test_dmi(void)
{
    static const unsigned char raw[] = {11, 5, 0, 0, 2, 'f', 'o', 'o', '=', '1', 0, 'c', 'e', 'r', 'i', 's', 'e', 'k', 'e', 'y', '=', 'a', 'b', 'c', 0, 0};
    char value[16];
    CHECK(fa_parse_dmi_type11(raw, sizeof(raw), "cerisekey", value, sizeof(value)) == FA_OK);
    CHECK(strcmp(value, "abc") == 0);
    CHECK(fa_parse_dmi_type11(raw, sizeof(raw), "missing", value, sizeof(value)) == FA_ERR_FORMAT);
}

static const unsigned char SMBIOS_TABLE[] = {
    1, 6, 1, 0, 1, 2, 'a', 0, 'b', 0, 0,
    11, 5, 2, 0, 1, 'c', 'e', 'r', 'i', 's', 'e', 'k', 'e', 'y', '=', 'a', 'b', 'c', 0, 0,
    127, 4, 3, 0, 0, 0
};

static void test_smbios_find(void)
{
    const unsigned char *structure = NULL;
    size_t structure_len = 0;
    char value[16];
    CHECK(fa_find_smbios_structure(SMBIOS_TABLE, sizeof(SMBIOS_TABLE), 11, &structure, &structure_len) == FA_OK);
    CHECK(structure == SMBIOS_TABLE + 11);
    CHECK(structure_len == 20);
    CHECK(fa_parse_dmi_type11(structure, structure_len, "cerisekey", value, sizeof(value)) == FA_OK);
    CHECK(strcmp(value, "abc") == 0);
    CHECK(fa_find_smbios_structure(SMBIOS_TABLE, sizeof(SMBIOS_TABLE), 1, &structure, &structure_len) == FA_OK);
    CHECK(structure == SMBIOS_TABLE && structure_len == 11);
    CHECK(fa_find_smbios_structure(SMBIOS_TABLE, sizeof(SMBIOS_TABLE), 4, &structure, &structure_len) == FA_ERR_FORMAT);
    CHECK(fa_find_smbios_structure(SMBIOS_TABLE, sizeof(SMBIOS_TABLE), 127, &structure, &structure_len) == FA_OK);
}

static void test_smbios_truncated(void)
{
    for (size_t cut = 0; cut < sizeof(SMBIOS_TABLE); cut++) {
        unsigned char *copy = malloc(cut ? cut : 1);
        const unsigned char *structure = NULL;
        size_t structure_len = 0;
        int status;
        CHECK(copy != NULL);
        memcpy(copy, SMBIOS_TABLE, cut);
        status = fa_find_smbios_structure(copy, cut, 11, &structure, &structure_len);
        CHECK(status == FA_OK || status == FA_ERR_FORMAT);
        if (cut < 31) CHECK(status == FA_ERR_FORMAT);
        free(copy);
    }
}

static void test_smbios_short_length(void)
{
    static const unsigned char table[] = {1, 3, 1, 0, 0, 0, 11, 5, 2, 0, 0, 0};
    const unsigned char *structure = NULL;
    size_t structure_len = 0;
    CHECK(fa_find_smbios_structure(table, sizeof(table), 11, &structure, &structure_len) == FA_ERR_FORMAT);
}

int main(void)
{
    test_round_trip();
    test_tamper();
    test_wrong_key_and_short();
    test_capacity();
    test_dmi();
    test_smbios_find();
    test_smbios_truncated();
    test_smbios_short_length();
    puts("all tests passed");
    return 0;
}
