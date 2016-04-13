#include "util.h"

#include <string.h>
#include <openssl/sha.h>
#include <sys/stat.h>

#define MIN(a, b) (a) < (b) ? (a) : (b)

int
countToN(int *a, int n)
{
	for (int i = 0; i < n; i++)
		a[i] = i;
	return 0;
}

mytime_t
current_time(void)
{
    unsigned int hi, lo;
    __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((unsigned long long) lo) | (((unsigned long long) hi) << 32);
    /* struct timespec tp; */
    /* (void) clock_gettime(CLOCK_MONOTONIC, &tp); */
    /* return 1000000000 * tp.tv_sec + tp.tv_nsec; */
}

static int
compare(const void * a, const void * b)
{
	return (*(mytime_t *) a - *(mytime_t *) b);
}

mytime_t
median(mytime_t *values, int n)
{
	qsort(values, n, sizeof(mytime_t), compare);
    if (n == 0)
        return 0;
    else if (n == 1)
        return values[0];
    else if (n % 2 == 1)
		return values[(n + 1) / 2 - 1];
	else
		return (values[n / 2 - 1] + values[n / 2]) / 2;
}

double
doubleMean(double *values, int n)
{
	double total = 0;
	for (int i = 0; i < n; i++)
		total += values[i];
	return total / n;
}

size_t
filesize(const char *fname)
{
	struct stat st;

	if (stat(fname, &st) == 0)
		return st.st_size;

	return -1;
}

/* block */
/* element_to_block(element_t elem) */
/* { */
/*     int length; */
/*     unsigned char *buf; */
/*     block out; */

/*     length = element_length_in_bytes_(elem); */
/*     buf = malloc(length); */
/*     (void) element_to_bytes_(buf, elem); */
/*     sha1_hash((char *) &out, sizeof out, buf, length); */
/*     free(buf); */
/*     return out; */
/* } */

block
hash(element_t elem, int idx, bool bit)
{
    SHA256_CTX sha;
    int length;
    unsigned char *buf;
    unsigned char h[SHA256_DIGEST_LENGTH];
    block out;

    /* element_printf("Hashing %B || %d || %d\n", elem, idx, bit); */

    length = element_length_in_bytes_(elem);
    buf = malloc(length);
    (void) element_to_bytes_(buf, elem);

    SHA256_Init(&sha);
    SHA256_Update(&sha, &idx, sizeof idx);
    SHA256_Update(&sha, &bit, sizeof bit);
    SHA256_Update(&sha, buf, length);
    SHA256_Final(h, &sha);
    memcpy(&out, h, sizeof out);
    /* block_printf("Result: %B\n", out); */
    free(buf);
    return out;
}

static void
sha256_hash(char *out, size_t outlen, const unsigned char *in, size_t inlen)
{
    unsigned int idx = 0;
    unsigned int length = 0;
    unsigned char hash[SHA256_DIGEST_LENGTH];

    while (length < outlen) {
        SHA256_CTX c;
        int n;

        (void) SHA256_Init(&c);
        (void) SHA256_Update(&c, &idx, sizeof idx);
        (void) SHA256_Update(&c, in, inlen);
        (void) SHA256_Final(hash, &c);
        n = MIN(outlen - length, sizeof hash);
        (void) memcpy(out + length, hash, n);
        length += n;
        idx++;
    }
}

block
commit(block in, block r)
{
    block out;
    block input[2];

    input[0] = in;
    input[1] = r;

    sha256_hash((char *) &out, sizeof out, (unsigned char *) &input, sizeof input);
    return out;
}

