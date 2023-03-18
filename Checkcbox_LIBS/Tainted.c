#include "Tainted.h"
bool isasciidigit (char c)
{
  return (c >= '0') && (c <= '9');
}

int
toxdigitvalue (char c)
{
  if (isasciidigit (c))
    return (unsigned char) (c - '0');
  if ( (c >= 'A') && (c <= 'F') )
    return (unsigned char) (c - 'A' + 10);
  if ( (c >= 'a') && (c <= 'f') )
    return (unsigned char) (c - 'a' + 10);

  return -1;
}

size_t
_T_MHD_strx_to_uint32_n_ (const char *str,
                       size_t maxlen,
                       uint32_t *out_val)
{
  size_t i;
  uint32_t res;
  int digit;
  if (! str || ! out_val)
    return 0;

  res = 0;
  i = 0;
  while (i < maxlen && (digit = toxdigitvalue (str[i])) >= 0)
  {
    if ( (res > (UINT32_MAX / 16)) ||
         ((res == (UINT32_MAX / 16)) && ( (uint32_t) digit > (UINT32_MAX
                                                              % 16)) ) )
      return 0;

    res *= 16;
    res += (unsigned int) digit;
    i++;
  }

  if (i)
    *out_val = res;
  return i;
}

size_t
MHD_http_unescape_2 (char* val)
{
  char *rpos = val;
  char *wpos = val;

  while ('\0' != *rpos)
  {
    uint32_t num;
    switch (*rpos)
    {
    case '%':
      if (2 == _T_MHD_strx_to_uint32_n_(rpos + 1,
                                      2,
                                      &num))
      {
        *wpos = (char) ((unsigned char) num);
        wpos++;
        rpos += 3;
        break;
      }
    /* TODO: add bad sequence handling */
    /* intentional fall through! */
    default:
      *wpos = *rpos;
      wpos++;
      rpos++;
    }
  }
  *wpos = '\0'; /* add 0-terminator */
  return wpos - val; /* = strlen(val) */
}

size_t
MHD_str_pct_decode_in_place_lenient_ (char* str,
                                      bool* broken_encoding)
{
#ifdef MHD_FAVOR_SMALL_CODE
  size_t len;
  size_t res;

  len = strlen (str);
  res = MHD_str_pct_decode_lenient_n_ (str, len, str, len, broken_encoding);
  str[res] = 0;

  return res;
#else  /* ! MHD_FAVOR_SMALL_CODE */
  size_t r;
  size_t w;
  if (NULL != broken_encoding)
    *broken_encoding = false;
  r = 0;
  w = 0;
  while (0 != str[r])
  {
    const char chr = str[r++];
    if ('%' == chr)
    {
      const char d1 = str[r++];
      if (0 == d1)
      {
        if (NULL != broken_encoding)
          *broken_encoding = true;
        str[w++] = chr; /* Copy "as is" */
        str[w] = 0;
        return w;
      }
      else
      {
        const char d2 = str[r++];
        if (0 == d2)
        {
          if (NULL != broken_encoding)
            *broken_encoding = true;
          str[w++] = chr; /* Copy "as is" */
          str[w++] = d1; /* Copy "as is" */
          str[w] = 0;
          return w;
        }
        else
        {
          const int h = toxdigitvalue (d1);
          const int l = toxdigitvalue (d2);
          unsigned char out;
          if ((0 > h) || (0 > l))
          {
            if (NULL != broken_encoding)
              *broken_encoding = true;
            str[w++] = chr; /* Copy "as is" */
            str[w++] = d1;
            str[w++] = d2;
            continue;
          }
          out = (unsigned char) ( (((uint8_t) ((unsigned int) h)) << 4)
                                  | ((uint8_t) ((unsigned int) l)) );
          str[w++] = (char) out;
          continue;
        }
      }
    }
    str[w++] = chr;
  }
  str[w] = 0;
  return w;
#endif /* ! MHD_FAVOR_SMALL_CODE */
}

size_t
MHD_str_pct_decode_lenient_n_ (const char* pct_encoded,
                               size_t pct_encoded_len,
                               char* decoded,
                               size_t buf_size,
                               bool* broken_encoding)
{
  size_t r;
  size_t w;
  r = 0;
  w = 0;
  if (NULL != broken_encoding)
    *broken_encoding = false;
#ifndef MHD_FAVOR_SMALL_CODE
  if (buf_size >= pct_encoded_len)
  {
    while (r < pct_encoded_len)
    {
      const char chr = pct_encoded[r];
      if ('%' == chr)
      {
        if (2 > pct_encoded_len - r)
        {
          if (NULL != broken_encoding)
            *broken_encoding = true;
          decoded[w] = chr; /* Copy "as is" */
        }
        else
        {
          const int h = toxdigitvalue (pct_encoded[++r]);
          const int l = toxdigitvalue (pct_encoded[++r]);
          unsigned char out;
          if ((0 > h) || (0 > l))
          {
            r -= 2;
            if (NULL != broken_encoding)
              *broken_encoding = true;
            decoded[w] = chr; /* Copy "as is" */
          }
          else
          {
            out = (unsigned char) ( (((uint8_t) ((unsigned int) h)) << 4)
                                    | ((uint8_t) ((unsigned int) l)) );
            decoded[w] = (char) out;
          }
        }
      }
      else
        decoded[w] = chr;
      ++r;
      ++w;
    }
    return w;
  }
#endif /* ! MHD_FAVOR_SMALL_CODE */
  while (r < pct_encoded_len)
  {
    const char chr = pct_encoded[r];
    if (w >= buf_size)
      return 0;
    if ('%' == chr)
    {
      if (2 > pct_encoded_len - r)
      {
        if (NULL != broken_encoding)
          *broken_encoding = true;
        decoded[w] = chr; /* Copy "as is" */
      }
      else
      {
        const int h = toxdigitvalue (pct_encoded[++r]);
        const int l = toxdigitvalue (pct_encoded[++r]);
        if ((0 > h) || (0 > l))
        {
          r -= 2;
          if (NULL != broken_encoding)
            *broken_encoding = true;
          decoded[w] = chr; /* Copy "as is" */
        }
        else
        {
          unsigned char out;
          out = (unsigned char) ( (((uint8_t) ((unsigned int) h)) << 4)
                                  | ((uint8_t) ((unsigned int) l)) );
          decoded[w] = (char) out;
        }
      }
    }
    else
      decoded[w] = chr;
    ++r;
    ++w;
  }
  return w;
}

size_t
MHD_str_pct_decode_strict_n_ (const char* pct_encoded,
                              size_t pct_encoded_len,
                              char* decoded,
                              size_t buf_size)
{
#ifdef MHD_FAVOR_SMALL_CODE
  bool broken;
  size_t res;

  res = MHD_str_pct_decode_lenient_n_ (pct_encoded, pct_encoded_len, decoded,
                                       buf_size, &broken);
  if (broken)
    return 0;
  return res;
#else  /* ! MHD_FAVOR_SMALL_CODE */
  size_t r;
  size_t w;
  r = 0;
  w = 0;

  if (buf_size >= pct_encoded_len)
  {
    while (r < pct_encoded_len)
    {
      const char chr = pct_encoded[r];
      if ('%' == chr)
      {
        if (2 > pct_encoded_len - r)
          return 0;
        else
        {
          const int h = toxdigitvalue (pct_encoded[++r]);
          const int l = toxdigitvalue (pct_encoded[++r]);
          unsigned char out;
          if ((0 > h) || (0 > l))
            return 0;
          out = (unsigned char) ( (((uint8_t) ((unsigned int) h)) << 4)
                                  | ((uint8_t) ((unsigned int) l)) );
          decoded[w] = (char) out;
        }
      }
      else
        decoded[w] = chr;
      ++r;
      ++w;
    }
    return w;
  }

  while (r < pct_encoded_len)
  {
    const char chr = pct_encoded[r];
    if (w >= buf_size)
      return 0;
    if ('%' == chr)
    {
      if (2 > pct_encoded_len - r)
        return 0;
      else
      {
        const int h = toxdigitvalue (pct_encoded[++r]);
        const int l = toxdigitvalue (pct_encoded[++r]);
        unsigned char out;
        if ((0 > h) || (0 > l))
          return 0;
        out = (unsigned char) ( (((uint8_t) ((unsigned int) h)) << 4)
                                | ((uint8_t) ((unsigned int) l)) );
        decoded[w] = (char) out;
      }
    }
    else
      decoded[w] = chr;
    ++r;
    ++w;
  }
  return w;
#endif /* ! MHD_FAVOR_SMALL_CODE */
}

size_t
MHD_str_pct_decode_in_place_strict_ (char *str)
{
#ifdef MHD_FAVOR_SMALL_CODE
  size_t res;
  bool broken;

  res = MHD_str_pct_decode_in_place_lenient_ (str, &broken);
  if (broken)
  {
    res = 0;
    str[0] = 0;
  }
  return res;
#else  /* ! MHD_FAVOR_SMALL_CODE */
  size_t r;
  size_t w;
  r = 0;
  w = 0;

  while (0 != str[r])
  {
    const char chr = str[r++];
    if ('%' == chr)
    {
      const char d1 = str[r++];
      if (0 == d1)
        return 0;
      else
      {
        const char d2 = str[r++];
        if (0 == d2)
          return 0;
        else
        {
          const int h = toxdigitvalue (d1);
          const int l = toxdigitvalue (d2);
          unsigned char out;
          if ((0 > h) || (0 > l))
            return 0;
          out = (unsigned char) ( (((uint8_t) ((unsigned int) h)) << 4)
                                  | ((uint8_t) ((unsigned int) l)) );
          str[w++] = (char) out;
        }
      }
    }
    else
      str[w++] = chr;
  }
  str[w] = 0;
  return w;
#endif /* ! MHD_FAVOR_SMALL_CODE */
}

bool MHD_str_equal_quoted_bin_n (const char* quoted,
                            size_t quoted_len,
                            const char* unquoted,
                            size_t unquoted_len)
{
  size_t i;
  size_t j;
  if (unquoted_len < quoted_len / 2)
    return false;

  j = 0;
  for (i = 0; quoted_len > i && unquoted_len > j; ++i, ++j)
  {
    if ('\\' == quoted[i])
    {
      i++; /* Advance to the next character */
      if (quoted_len == i)
        return false; /* No character after escaping backslash */
    }
    if (quoted[i] != unquoted[j])
      return false; /* Different characters */
  }
  if ((quoted_len != i) || (unquoted_len != j))
    return false; /* The strings have different length */

  return true;
}

bool
_T_MHD_str_equal_caseless_quoted_bin_n (const char* quoted,
                                     size_t quoted_len,
                                     const char* unquoted,
                                     size_t unquoted_len)
{
  size_t i;
  size_t j;
  if (unquoted_len < quoted_len / 2)
    return false;

  j = 0;
  for (i = 0; quoted_len > i && unquoted_len > j; ++i, ++j)
  {
    if ('\\' == quoted[i])
    {
      i++; /* Advance to the next character */
      if (quoted_len == i)
        return false; /* No character after escaping backslash */
    }
    if (! charsequalcaseless (quoted[i], unquoted[j]))
      return false; /* Different characters */
  }
  if ((quoted_len != i) || (unquoted_len != j))
    return false; /* The strings have different length */

  return true;
}

size_t
_T_MHD_str_unquote (const char* quoted,
                 size_t quoted_len,
                 char* result)
{
  size_t r;
  size_t w;

  r = 0;
  w = 0;

  while (quoted_len > r)
  {
    if ('\\' == quoted[r])
    {
      ++r;
      if (quoted_len == r)
        return 0; /* Last backslash is not followed by char to unescape */
    }
    result[w++] = quoted[r++];
  }
  return w;
}

size_t
_T_MHD_str_quote (const char* unquoted,
               size_t unquoted_len,
               char* result,
               size_t buf_size)
{
  size_t r;
  size_t w;

  r = 0;
  w = 0;

#ifndef MHD_FAVOR_SMALL_CODE
  if (unquoted_len * 2 <= buf_size)
  {
    /* Fast loop: the output will fit the buffer with any input string content */
    while (unquoted_len > r)
    {
      const char chr = unquoted[r++];
      if (('\\' == chr) || ('\"' == chr))
        result[w++] = '\\'; /* Escape current char */
      result[w++] = chr;
    }
  }
  else
  {
    if (unquoted_len > buf_size)
      return 0; /* Quick fail: the output buffer is too small */
#else  /* MHD_FAVOR_SMALL_CODE */
  if (1)
  {
#endif /* MHD_FAVOR_SMALL_CODE */

    while (unquoted_len > r)
    {
      if (buf_size <= w)
        return 0; /* The output buffer is too small */
      else
      {
        const char chr = unquoted[r++];
        if (('\\' == chr) || ('\"' == chr))
        {
          result[w++] = '\\'; /* Escape current char */
          if (buf_size <= w)
            return 0; /* The output buffer is too small */
        }
        result[w++] = chr;
      }
    }
  }

  mhd_assert (w >= r);
  mhd_assert (w <= r * 2);
  return w;
}

bool
charsequalcaseless (const char c1, const char c2)
{
  return ( (c1 == c2) ||
           (isasciiupper (c1) ?
            ((c1 - 'A' + 'a') == c2) :
            ((c1 == (c2 - 'A' + 'a')) && isasciiupper (c2))) );
}

bool
isasciiupper (char c)
{
  return (c >= 'A') && (c <= 'Z');
}

size_t
_T_MHD_base64_to_bin_n (const char* base64,
                     size_t base64_len,
                     void* bin,
                     size_t bin_size)
{
#ifndef MHD_FAVOR_SMALL_CODE
#define map_type int
#else  /* MHD_FAVOR_SMALL_CODE */
#define map_type int8_t
#endif /* MHD_FAVOR_SMALL_CODE */
  static const map_type map[] = {
    /* -1 = invalid char, -2 = padding
     0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  A,  B,  C,  D,  E,  F */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,  /* 00..0F */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,  /* 10..1F */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,  /* 20..2F */
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -2, -1, -1,  /* 30..3F */
    -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,  /* 40..4F */
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,  /* 50..5F */
    -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,  /* 60..6F */
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1   /* 70..7F */
#ifndef MHD_FAVOR_SMALL_CODE
    ,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,  /* 80..8F */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,  /* 90..9F */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,  /* A0..AF */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,  /* B0..BF */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,  /* C0..CF */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,  /* D0..DF */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,  /* E0..EF */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,  /* F0..FF */
#endif /* ! MHD_FAVOR_SMALL_CODE */
  };
  const uint8_t *const in = (const uint8_t *) base64;
  uint8_t *const out = (uint8_t *) bin;
  size_t i;
  size_t j;
  if (0 == base64_len)
    return 0;  /* Nothing to decode */
  if (0 != base64_len % 4)
    return 0;  /* Wrong input length */
  if (base64_len / 4 * 3 - 2 > bin_size)
    return 0;

  j = 0;
  for (i = 0; i < (base64_len - 4); i += 4)
  {
#ifdef MHD_FAVOR_SMALL_CODE
    if (0 != (0x80 & (in[i] | in[i + 1] | in[i + 2] | in[i + 3])))
      return 0;
#endif /* MHD_FAVOR_SMALL_CODE */
    if (1)
    {
      const map_type v1 = map[in[i + 0]];
      const map_type v2 = map[in[i + 1]];
      const map_type v3 = map[in[i + 2]];
      const map_type v4 = map[in[i + 3]];
      if ((0 > v1) || (0 > v2) || (0 > v3) || (0 > v4))
        return 0;
      out[j + 0] = (uint8_t) ((((uint8_t) v1) << 2) | (((uint8_t) v2) >> 4));
      out[j + 1] = (uint8_t) ((((uint8_t) v2) << 4) | (((uint8_t) v3) >> 2));
      out[j + 2] = (uint8_t) ((((uint8_t) v3) << 6) | (((uint8_t) v4)));
    }
    j += 3;
  }
#ifdef MHD_FAVOR_SMALL_CODE
  if (0 != (0x80 & (in[i] | in[i + 1] | in[i + 2] | in[i + 3])))
    return 0;
#endif /* MHD_FAVOR_SMALL_CODE */
  if (1)
  { /* The last four chars block */
    const map_type v1 = map[in[i + 0]];
    const map_type v2 = map[in[i + 1]];
    const map_type v3 = map[in[i + 2]];
    const map_type v4 = map[in[i + 3]];
    if ((0 > v1) || (0 > v2))
      return 0; /* Invalid char or padding at first two positions */
    mhd_assert (j < bin_size);
    out[j++] = (uint8_t) ((((uint8_t) v1) << 2) | (((uint8_t) v2) >> 4));
    if (0 > v3)
    { /* Third char is either padding or invalid */
      if ((-2 != v3) || (-2 != v4))
        return 0;  /* Both two last chars must be padding */
      if (0 != (uint8_t) (((uint8_t) v2) << 4))
        return 0;  /* Wrong last char */
      return j;
    }
    if (j >= bin_size)
      return 0; /* Not enough space */
    out[j++] = (uint8_t) ((((uint8_t) v2) << 4) | (((uint8_t) v3) >> 2));
    if (0 > v4)
    { /* Fourth char is either padding or invalid */
      if (-2 != v4)
        return 0;  /* The char must be padding */
      if (0 != (uint8_t) (((uint8_t) v3) << 6))
        return 0;  /* Wrong last char */
      return j;
    }
    if (j >= bin_size)
      return 0; /* Not enough space */
    out[j++] = (uint8_t) ((((uint8_t) v3) << 6) | (((uint8_t) v4)));
  }
  return j;
#undef map_type
}

void simple(void)
{
        int* ptr = (int*)malloc(1);
        ptr = (int*)calloc(2, sizeof(int));
        ptr = realloc(ptr, 1 * sizeof(int));
        free(ptr);
}


