#include "util.h"

#include <string.h>
#include <openssl/sha.h>
#include <sys/stat.h>

#define MIN(a, b) (a) < (b) ? (a) : (b)

size_t
filesize(const char *fname)
{
	struct stat st;

	if (stat(fname, &st) == 0)
		return st.st_size;

	return -1;
}

static void
sha1_hash(char *out, size_t outlen, const unsigned char *in, size_t inlen)
{
    unsigned int idx = 0;
    unsigned int length = 0;
    unsigned char hash[SHA_DIGEST_LENGTH];

    while (length < outlen) {
        SHA_CTX c;
        int n;

        (void) SHA1_Init(&c);
        (void) SHA1_Update(&c, &idx, sizeof idx);
        (void) SHA1_Update(&c, in, inlen);
        (void) SHA1_Final(hash, &c);
        n = MIN(outlen - length, sizeof hash);
        (void) memcpy(out + length, hash, n);
        length += n;
        idx++;
    }
}

block
element_to_block(element_t elem)
{
    int length;
    unsigned char *buf;
    block out;

    length = element_length_in_bytes_(elem);
    buf = malloc(length);
    (void) element_to_bytes_(buf, elem);
    sha1_hash((char *) &out, sizeof out, buf, length);
    free(buf);
    return out;
}

block
commit(block in, block r)
{
    block out;
    block input[2];

    input[0] = in;
    input[1] = r;

    sha1_hash((char *) &out, sizeof out, (unsigned char *) &input, sizeof input);
    return out;
}

