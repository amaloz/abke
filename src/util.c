#include "util.h"

#include <string.h>
#include <openssl/sha.h>
#include <sys/stat.h>

#ifndef MIN
#define MIN(a, b) (a) < (b) ? (a) : (b)
#endif

#define COMPRESS 1

size_t
g1_length_in_bytes_(g1_t e)
{
    return g1_size_bin(e, COMPRESS);
}
size_t
g2_length_in_bytes_(g2_t e)
{
    return g2_size_bin(e, COMPRESS);
}

size_t
g1_to_bytes_(uint8_t *buf, g1_t e)
{
    size_t size = g1_size_bin(e, COMPRESS);
    g1_write_bin(buf, size, e, COMPRESS);
    return size;
}
size_t
g2_to_bytes_(uint8_t *buf, g2_t e)
{
    size_t size = g2_size_bin(e, COMPRESS);
    g2_write_bin(buf, size, e, COMPRESS);
    return size;
}
size_t
bn_to_bytes_(uint64_t *buf, bn_t e)
{
    size_t size = bn_size_raw(e);
    bn_write_raw(buf, size, e);
    return size;
}

size_t
g1_from_bytes_(g1_t e, uint8_t *buf)
{
    size_t size = g1_size_bin(e, COMPRESS);
    g1_read_bin(e, buf, size);
    return size;
}
size_t
g2_from_bytes_(g2_t e, uint8_t *buf)
{
    size_t size = g2_size_bin(e, COMPRESS);
    g2_read_bin(e, buf, size);
    return size;
}
size_t
bn_from_bytes_(bn_t e, uint64_t *buf)
{
    size_t size = bn_size_raw(e);
    bn_read_raw(e, buf, size);
    return size;
}


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

block
hash(g1_t elem, int idx, bool bit)
{
    SHA256_CTX sha;
    int length;
    unsigned char *buf;
    unsigned char h[SHA256_DIGEST_LENGTH];
    block out;

    length = g1_size_bin(elem, 1);
    buf = malloc(length);
    (void) g1_write_bin(buf, length, elem, 1);

    SHA256_Init(&sha);
    SHA256_Update(&sha, &idx, sizeof idx);
    SHA256_Update(&sha, &bit, sizeof bit);
    SHA256_Update(&sha, buf, length);
    SHA256_Final(h, &sha);
    memcpy(&out, h, sizeof out);
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

/* taken from pbc_get_time() */
double
get_time(void)
{
    static struct timeval last_tv, tv;
    static int first = 1;
    static double res = 0;

    if (first) {
        gettimeofday(&last_tv, NULL);
        first = 0;
        return 0;
    } else {
        gettimeofday(&tv, NULL);
        res += tv.tv_sec - last_tv.tv_sec;
        res += (tv.tv_usec - last_tv.tv_usec) / 1000000.0;
        last_tv = tv;

        return res;
    }
}
