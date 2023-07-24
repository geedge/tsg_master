#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/md5.h>

#ifndef MIN
#define MIN(a, b) ((a) > (b) ? (b) : (a))
#endif

#define BSB_INIT(b, buffer, size)                     \
    do                                                \
    {                                                 \
        (b).buf = (unsigned char *)buffer;            \
        (b).ptr = (unsigned char *)buffer;            \
        int s = (int)size;                            \
        if ((buffer == NULL) || (s < 0))              \
            (b).end = 0;                              \
        else                                          \
            (b).end = (unsigned char *)buffer + size; \
    } while (0)

#define BSB_SET_ERROR(b) ((b).end = NULL)
#define BSB_IS_ERROR(b) ((b).end == NULL)
#define BSB_NOT_ERROR(b) ((b).end != NULL)
#define BSB_LENGTH(b) ((b).ptr - (b).buf)
#define BSB_POSITION BSB_LENGTH
#define BSB_SIZE(b) ((b).end - (b).buf)
#define BSB_REMAINING(b) ((b).end ? (b).end - (b).ptr : 0)
#define BSB_WORK_PTR(b) ((b).ptr)

#define BSB_EXPORT_u08(b, x)                   \
    do                                         \
    {                                          \
        if ((b).ptr && (b).ptr + 1 <= (b).end) \
        {                                      \
            *(((b).ptr)++) = (unsigned char)x; \
        }                                      \
        else                                   \
            BSB_SET_ERROR(b);                  \
    } while (0)

#define BSB_EXPORT_u16(b, x)                    \
    do                                          \
    {                                           \
        if ((b).ptr && (b).ptr + 2 <= (b).end)  \
        {                                       \
            uint16_t t = (uint16_t)x;           \
            *(((b).ptr)++) = (t & 0xff00) >> 8; \
            *(((b).ptr)++) = (t & 0x00ff);      \
        }                                       \
        else                                    \
            BSB_SET_ERROR(b);                   \
    } while (0)

#define BSB_EXPORT_u32(b, x)                         \
    do                                               \
    {                                                \
        if ((b).ptr && (b).ptr + 4 <= (b).end)       \
        {                                            \
            uint32_t t = x;                          \
            *(((b).ptr)++) = (t & 0xff000000) >> 24; \
            *(((b).ptr)++) = (t & 0x00ff0000) >> 16; \
            *(((b).ptr)++) = (t & 0x0000ff00) >> 8;  \
            *(((b).ptr)++) = (t & 0x000000ff);       \
        }                                            \
        else                                         \
            BSB_SET_ERROR(b);                        \
    } while (0)

#define BSB_EXPORT_ptr(b, x, size)       \
    do                                   \
    {                                    \
        if ((x || size == 0) &&          \
            (b).ptr + size <= (b).end && \
            (b).ptr + size >= (b).buf)   \
        {                                \
            memcpy((b).ptr, x, size);    \
            (b).ptr += size;             \
        }                                \
        else                             \
            BSB_SET_ERROR(b);            \
    } while (0)

#define BSB_EXPORT_ptr_some(b, x, size)           \
    do                                            \
    {                                             \
        if ((b).ptr + size <= (b).end)            \
        {                                         \
            memcpy((b).ptr, x, size);             \
            (b).ptr += size;                      \
        }                                         \
        else if (BSB_NOT_ERROR(b))                \
        {                                         \
            memcpy((b).ptr, x, BSB_REMAINING(b)); \
            (b).ptr += BSB_REMAINING(b);          \
        }                                         \
    } while (0)

#define BSB_EXPORT_cstr(b, x)          \
    do                                 \
    {                                  \
        const int size = sizeof x - 1; \
        if ((b).ptr + size <= (b).end) \
        {                              \
            memcpy((b).ptr, x, size);  \
            (b).ptr += size;           \
        }                              \
        else                           \
            BSB_SET_ERROR(b);          \
    } while (0)

#define BSB_EXPORT_skip(b, size)         \
    do                                   \
    {                                    \
        if ((b).ptr + size <= (b).end && \
            (b).ptr + size >= (b).buf)   \
        {                                \
            (b).ptr += size;             \
            if ((b).ptr < (b).buf)       \
                (b).end = 0;             \
        }                                \
        else                             \
            BSB_SET_ERROR(b);            \
    } while (0)

#define BSB_EXPORT_rewind(b, size)       \
    do                                   \
    {                                    \
        if ((b).ptr - size <= (b).end && \
            (b).ptr - size >= (b).buf)   \
        {                                \
            (b).ptr -= size;             \
            if ((b).ptr < (b).buf)       \
                (b).end = 0;             \
        }                                \
        else                             \
        {                                \
            BSB_SET_ERROR(b);            \
        }                                \
    } while (0)

#if defined(C9X)

#define BSB_EXPORT_sprintf(b, ...)              \
    do                                          \
    {                                           \
        if ((b).end != 0)                       \
        {                                       \
            int l = snprintf((char *)(b).ptr,   \
                             (b).end - (b).ptr, \
                             __VA_ARGS__);      \
            if (l <= (b).end - (b).ptr)         \
            {                                   \
                (b).ptr += l;                   \
            }                                   \
            else                                \
            {                                   \
                BSB_SET_ERROR(b);               \
            }                                   \
        }                                       \
    } while (0)

#else

#define BSB_EXPORT_sprintf(b, args...)          \
    do                                          \
    {                                           \
        if ((b).end != 0)                       \
        {                                       \
            int l = snprintf((char *)(b).ptr,   \
                             (b).end - (b).ptr, \
                             ##args);           \
            if (l <= (b).end - (b).ptr)         \
            {                                   \
                (b).ptr += l;                   \
            }                                   \
            else                                \
            {                                   \
                BSB_SET_ERROR(b);               \
            }                                   \
        }                                       \
    } while (0)
#endif

#define BSB_IMPORT_u08(b, x)                   \
    do                                         \
    {                                          \
        if ((b).ptr && (b).ptr + 1 <= (b).end) \
        {                                      \
            x = *(((b).ptr)++);                \
        }                                      \
        else                                   \
            BSB_SET_ERROR(b);                  \
    } while (0)

#define BSB_IMPORT_u16(b, x)                    \
    do                                          \
    {                                           \
        if ((b).ptr && (b).ptr + 2 <= (b).end)  \
        {                                       \
            x = ((uint16_t)((b).ptr)[0]) << 8 | \
                ((uint16_t)((b).ptr)[1]);       \
            (b).ptr += 2;                       \
        }                                       \
        else                                    \
            BSB_SET_ERROR(b);                   \
    } while (0)

#define BSB_IMPORT_u24(b, x)                     \
    do                                           \
    {                                            \
        if ((b).ptr && (b).ptr + 3 <= (b).end)   \
        {                                        \
            x = ((uint32_t)((b).ptr)[0]) << 16 | \
                ((uint32_t)((b).ptr)[1]) << 8 |  \
                ((uint32_t)((b).ptr)[2]);        \
            (b).ptr += 3;                        \
        }                                        \
        else                                     \
            BSB_SET_ERROR(b);                    \
    } while (0)

#define BSB_IMPORT_u32(b, x)                     \
    do                                           \
    {                                            \
        if ((b).ptr && (b).ptr + 4 <= (b).end)   \
        {                                        \
            x = ((uint32_t)((b).ptr)[0]) << 24 | \
                ((uint32_t)((b).ptr)[1]) << 16 | \
                ((uint32_t)((b).ptr)[2]) << 8 |  \
                ((uint32_t)((b).ptr)[3]);        \
            (b).ptr += 4;                        \
        }                                        \
        else                                     \
            BSB_SET_ERROR(b);                    \
    } while (0)

#define BSB_LEXPORT_u08(b, x) BSB_EXPORT_u08(b, x)

#define BSB_LEXPORT_u16(b, x)                   \
    do                                          \
    {                                           \
        if ((b).ptr + 2 <= (b).end)             \
        {                                       \
            uint16_t t = (uint16_t)x;           \
            *(((b).ptr)++) = (t & 0x00ff);      \
            *(((b).ptr)++) = (t & 0xff00) >> 8; \
        }                                       \
        else                                    \
            BSB_SET_ERROR(b);                   \
    } while (0)

#define BSB_LEXPORT_u32(b, x)                        \
    do                                               \
    {                                                \
        if ((b).ptr + 4 <= (b).end)                  \
        {                                            \
            uint32_t t = x;                          \
            *(((b).ptr)++) = (t & 0x000000ff);       \
            *(((b).ptr)++) = (t & 0x0000ff00) >> 8;  \
            *(((b).ptr)++) = (t & 0x00ff0000) >> 16; \
            *(((b).ptr)++) = (t & 0xff000000) >> 24; \
        }                                            \
        else                                         \
            BSB_SET_ERROR(b);                        \
    } while (0)

#define BSB_LIMPORT_u08(b, x) BSB_IMPORT_u08(b, x)

#define BSB_LIMPORT_u16(b, x)                   \
    do                                          \
    {                                           \
        if ((b).ptr + 2 <= (b).end)             \
        {                                       \
            x = ((uint16_t)((b).ptr)[1]) << 8 | \
                ((uint16_t)((b).ptr)[0]);       \
            (b).ptr += 2;                       \
        }                                       \
        else                                    \
            BSB_SET_ERROR(b);                   \
    } while (0)

#define BSB_LIMPORT_u24(b, x)                    \
    do                                           \
    {                                            \
        if ((b).ptr + 3 <= (b).end)              \
        {                                        \
            x = ((uint32_t)((b).ptr)[2]) << 16 | \
                ((uint32_t)((b).ptr)[1]) << 8 |  \
                ((uint32_t)((b).ptr)[0]);        \
            (b).ptr += 3;                        \
        }                                        \
        else                                     \
            BSB_SET_ERROR(b);                    \
    } while (0)

#define BSB_LIMPORT_u32(b, x)                    \
    do                                           \
    {                                            \
        if ((b).ptr + 4 <= (b).end)              \
        {                                        \
            x = ((uint32_t)((b).ptr)[3]) << 24 | \
                ((uint32_t)((b).ptr)[2]) << 16 | \
                ((uint32_t)((b).ptr)[1]) << 8 |  \
                ((uint32_t)((b).ptr)[0]);        \
            (b).ptr += 4;                        \
        }                                        \
        else                                     \
            BSB_SET_ERROR(b);                    \
    } while (0)

#define BSB_IMPORT_ptr(b, x, size)       \
    do                                   \
    {                                    \
        if ((b).ptr + size <= (b).end && \
            (b).ptr + size >= (b).buf)   \
        {                                \
            (x) = (b).ptr;               \
            (b).ptr += size;             \
        }                                \
        else                             \
        {                                \
            BSB_SET_ERROR(b);            \
            x = 0;                       \
        }                                \
    } while (0)

#define BSB_LIMPORT_ptr BSB_IMPORT_ptr
#define BSB_IMPORT_skip BSB_EXPORT_skip
#define BSB_LIMPORT_skip BSB_EXPORT_skip
#define BSB_IMPORT_rewind BSB_EXPORT_rewind
#define BSB_LIMPORT_rewind BSB_EXPORT_rewind

#define BSB_memchr(b, ch, pos)                                 \
    do                                                         \
    {                                                          \
        if (BSB_IS_ERROR(b))                                   \
        {                                                      \
            pos = 0;                                           \
            break;                                             \
        }                                                      \
        char *s = memchr((char *)b.ptr, ch, BSB_REMAINING(b)); \
        if (s)                                                 \
            pos = (char *)s - (char *)b.ptr;                   \
        else                                                   \
            pos = 0;                                           \
    } while (0)

#define BSB_memcmp(str, b, len) ((b).ptr + len <= (b).end ? memcmp(str, b.ptr, len) : -1)

#define BSB_PEEK(b) ((b).ptr + 1 <= (b).end ? *b.ptr : -1)

#define BSB_IMPORT_zbyte(b, x, size)   \
    do                                 \
    {                                  \
        if ((b).ptr + size <= (b).end) \
        {                              \
            memcpy(x, b, size);        \
            (x)[size] = 0;             \
            (b).ptr += size;           \
        }                              \
        else                           \
        {                              \
            BSB_SET_ERROR(b);          \
            (x)[0] = 0;                \
        }                              \
    } while (0)

/* Private data structure */
typedef struct bsb
{
    unsigned char *buf;
    unsigned char *ptr;
    unsigned char *end;
} BSB;

int ja3_md5sum(const char *str, int len, char *buf, int size)
{
    int n;
    int ret = 0;
    MD5_CTX ctx;
    unsigned char tmp[MD5_DIGEST_LENGTH];

    MD5_Init(&ctx);
    MD5_Update(&ctx, str, len);
    MD5_Final(tmp, &ctx);

    for (n = 0; n < MD5_DIGEST_LENGTH; n++)
    {
        ret += snprintf(buf + ret, size - ret, "%.2x", tmp[n]);
    }

    return ret;
}


// https://tools.ietf.org/html/draft-davidben-tls-grease-00
static int tls_is_grease_value(uint32_t val)
{
    if ((val & 0x0f) != 0x0a)
        return 0;

    if ((val & 0xff) != ((val >> 8) & 0xff))
        return 0;

    return 1;
}

static int ssl_generate_ja3_fingerprint(const unsigned char *data, int len, char *ja3_fp, int ja3_fp_len, char *sni_buff, int sni_buff_len)
{
    BSB sslbsb;
    //char ja3[30000];
    BSB ja3bsb;
    char ecfja3[1000];
    BSB ecfja3bsb;
    char eja3[10000];
    BSB eja3bsb;
    char ecja3[10000];
    BSB ecja3bsb;

    BSB_INIT(sslbsb, data, len);
    BSB_INIT(ja3bsb, ja3_fp, ja3_fp_len);
    BSB_INIT(ecja3bsb, ecja3, sizeof(ecja3));
    BSB_INIT(ecfja3bsb, ecfja3, sizeof(ecfja3));
    BSB_INIT(eja3bsb, eja3, sizeof(eja3));

    if (BSB_REMAINING(sslbsb) > 5)
    {
        unsigned char *ssldata = BSB_WORK_PTR(sslbsb);
        int ssllen = MIN(BSB_REMAINING(sslbsb) - 5, ssldata[3] << 8 | ssldata[4]);

        BSB pbsb;
        BSB_INIT(pbsb, ssldata + 5, ssllen);

        if (BSB_REMAINING(pbsb) > 7)
        {
            unsigned char *pdata = BSB_WORK_PTR(pbsb);
            int plen = MIN(BSB_REMAINING(pbsb) - 4, pdata[2] << 8 | pdata[3]);

            uint16_t ver = 0;
            BSB_IMPORT_skip(pbsb, 4); // type + len
            BSB_IMPORT_u16(pbsb, ver);

            BSB_EXPORT_sprintf(ja3bsb, "%d,", ver);

            BSB cbsb;
            BSB_INIT(cbsb, pdata + 6, plen - 2); // The - 4 for plen is done above, confusing

            if (BSB_REMAINING(cbsb) > 32)
            {
                BSB_IMPORT_skip(cbsb, 32); // Random

                int skiplen = 0;
                BSB_IMPORT_u08(cbsb, skiplen); // Session Id Length
                if (skiplen > 0 && BSB_REMAINING(cbsb) > skiplen)
                {
                    // unsigned char *ptr = BSB_WORK_PTR(cbsb);
                    // char sessionId[513];
                    // int i;

                    // for (i = 0; i < skiplen; i++)
                    // {
                    //     sessionId[i * 2] = moloch_char_to_hexstr[ptr[i]][0];
                    //     sessionId[i * 2 + 1] = moloch_char_to_hexstr[ptr[i]][1];
                    // }
                    // sessionId[skiplen * 2] = 0;
                    // moloch_field_string_add(srcIdField, session, sessionId, skiplen * 2, TRUE);
                }
                BSB_IMPORT_skip(cbsb, skiplen); // Session Id

                BSB_IMPORT_u16(cbsb, skiplen); // Ciper Suites Length
                while (BSB_NOT_ERROR(cbsb) && skiplen > 0)
                {
                    uint16_t c = 0;
                    BSB_IMPORT_u16(cbsb, c);
                    if (!tls_is_grease_value(c))
                    {
                        BSB_EXPORT_sprintf(ja3bsb, "%d-", c);
                    }
                    skiplen -= 2;
                }
                BSB_EXPORT_rewind(ja3bsb, 1); // Remove last -
                BSB_EXPORT_u08(ja3bsb, ',');

                BSB_IMPORT_u08(cbsb, skiplen);  // Compression Length
                BSB_IMPORT_skip(cbsb, skiplen); // Compressions

                if (BSB_REMAINING(cbsb) > 6)
                {
                    int etotlen = 0;
                    BSB_IMPORT_u16(cbsb, etotlen); // Extensions Length

                    etotlen = MIN(etotlen, BSB_REMAINING(cbsb));

                    BSB ebsb;
                    BSB_INIT(ebsb, BSB_WORK_PTR(cbsb), etotlen);

                    while (BSB_REMAINING(ebsb) > 4)
                    {
                        uint16_t etype = 0, elen = 0;

                        BSB_IMPORT_u16(ebsb, etype);
                        BSB_IMPORT_u16(ebsb, elen);

                        if (!tls_is_grease_value(etype))
                            BSB_EXPORT_sprintf(eja3bsb, "%d-", etype);

                        if (elen > BSB_REMAINING(ebsb))
                            break;

                        if (etype == 0)
                        { // SNI
                            BSB snibsb;
                            BSB_INIT(snibsb, BSB_WORK_PTR(ebsb), elen);
                            BSB_IMPORT_skip(ebsb, elen);

                            int sni = 0;
                            BSB_IMPORT_u16(snibsb, sni); // list len
                            if (sni != BSB_REMAINING(snibsb))
                                continue;

                            BSB_IMPORT_u08(snibsb, sni); // type
                            if (sni != 0)
                                continue;

                            BSB_IMPORT_u16(snibsb, sni); // len
                            if (sni != BSB_REMAINING(snibsb))
                                continue;

							memcpy(sni_buff, (char *)BSB_WORK_PTR(snibsb), (sni>sni_buff_len ? sni_buff_len : sni));
                            // moloch_field_string_add(hostField, session, (char *)BSB_WORK_PTR(snibsb), sni, TRUE);
                        }
                        else if (etype == 0x000a)
                        { // Elliptic Curves
                            BSB bsb;
                            BSB_INIT(bsb, BSB_WORK_PTR(ebsb), elen);
                            BSB_IMPORT_skip(ebsb, elen);

                            uint16_t llen = 0;
                            BSB_IMPORT_u16(bsb, llen); // list len
                            while (llen > 0 && !BSB_IS_ERROR(bsb))
                            {
                                uint16_t c = 0;
                                BSB_IMPORT_u16(bsb, c);
                                if (!tls_is_grease_value(c))
                                {
                                    BSB_EXPORT_sprintf(ecja3bsb, "%d-", c);
                                }
                                llen -= 2;
                            }
                            BSB_EXPORT_rewind(ecja3bsb, 1); // Remove last -
                        }
                        else if (etype == 0x000b)
                        { // Elliptic Curves point formats
                            BSB bsb;
                            BSB_INIT(bsb, BSB_WORK_PTR(ebsb), elen);
                            BSB_IMPORT_skip(ebsb, elen);

                            uint16_t llen = 0;
                            BSB_IMPORT_u08(bsb, llen); // list len
                            while (llen > 0 && !BSB_IS_ERROR(bsb))
                            {
                                uint8_t c = 0;
                                BSB_IMPORT_u08(bsb, c);
                                BSB_EXPORT_sprintf(ecfja3bsb, "%d-", c);
                                llen -= 1;
                            }
                            BSB_EXPORT_rewind(ecfja3bsb, 1); // Remove last -
                        }
                        else
                        {
                            BSB_IMPORT_skip(ebsb, elen);
                        }
                    }
                    BSB_EXPORT_rewind(eja3bsb, 1); // Remove last -
                }
            }
        }
        BSB_IMPORT_skip(sslbsb, ssllen + 5);

        if (BSB_LENGTH(ja3bsb) > 0 && BSB_NOT_ERROR(ja3bsb) && BSB_NOT_ERROR(ecja3bsb) && BSB_NOT_ERROR(eja3bsb) && BSB_NOT_ERROR(ecfja3bsb))
        {
            BSB_EXPORT_sprintf(ja3bsb, "%.*s,%.*s,%.*s", (int)BSB_LENGTH(eja3bsb), eja3, (int)BSB_LENGTH(ecja3bsb), ecja3, (int)BSB_LENGTH(ecfja3bsb), ecfja3);
        }
		return 1;
    }

    return 0;
}

int tsg_ssl_ja3_fingerprint_generate(const unsigned char *buff, int buff_len, char *ja3_fingerprint, int n_ja3_fingerprint, int thread_seq)
{
    if(n_ja3_fingerprint<(2*MD5_DIGEST_LENGTH+1) || buff_len<=0 || buff==NULL)
    {
        return 0;
    }

	char ja3_fp[8192]={0};
	char sni_buff[1024]={0};
	
	int ret=ssl_generate_ja3_fingerprint(buff, buff_len, ja3_fp, sizeof(ja3_fp), sni_buff, sizeof(sni_buff));
	if(ret==1 && strlen(ja3_fp)>0)
	{
        return ja3_md5sum(ja3_fp, strlen(ja3_fp), ja3_fingerprint, n_ja3_fingerprint);
	}

	return 0;
}