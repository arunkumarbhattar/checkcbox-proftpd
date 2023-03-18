#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#define mhd_assert(CHK) assert (CHK)

bool isasciidigit (char c);
int
toxdigitvalue (char c);
size_t
_T_MHD_strx_to_uint32_n_ (const char *str,
                       size_t maxlen,
                       uint32_t *out_val);
size_t
MHD_http_unescape_2 (char* val);
size_t
MHD_str_pct_decode_lenient_n_ (const char* pct_encoded,
                               size_t pct_encoded_len,
                               char* decoded,
                               size_t buf_size,
                               bool* broken_encoding);
size_t
MHD_str_pct_decode_strict_n_ (const char* pct_encoded,
                              size_t pct_encoded_len,
                              char* decoded,
                              size_t buf_size);
size_t
MHD_str_pct_decode_in_place_strict_ (char *str);

bool MHD_str_equal_quoted_bin_n (const char* quoted,
                            size_t quoted_len,
                            const char* unquoted,
                            size_t unquoted_len);

bool
_T_MHD_str_equal_caseless_quoted_bin_n (const char* quoted,
                                     size_t quoted_len,
                                     const char* unquoted,
                                     size_t unquoted_len);

size_t
_T_MHD_str_unquote (const char* quoted,
                 size_t quoted_len,
                 char* result);

size_t
_T_MHD_str_quote (const char* unquoted,
               size_t unquoted_len,
               char* result,
               size_t buf_size);

bool
charsequalcaseless (const char c1, const char c2);
bool
isasciiupper (char c);

size_t
_T_MHD_base64_to_bin_n (const char* base64,
                     size_t base64_len,
                     void* bin,
                     size_t bin_size);
