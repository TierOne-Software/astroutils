/*
 * fuzz_zopen.c — libFuzzer harness for the compress/zopen LZW
 * decoder (src.freebsd/compress/zopen.c: zopen/zread/getcode).
 * Historic CVE class: LZW table/stack overflows in *compress
 * decompressors fed crafted .Z streams.
 *
 * zopen(3) takes a pathname.  Two paths are exercised per input:
 *
 *   1. decode: the fuzzer bytes are staged in a memfd and handed to
 *      zopen() via /proc/self/fd/<n>, then fread() to EOF — the raw
 *      fuzzer bytes are treated as a .Z stream (bad magic, bogus
 *      n_bits, out-of-range codes, CLEAR floods all land here).
 *   2. roundtrip: zopen(tmpfile, "w") + fwrite of the fuzzer bytes,
 *      then re-read through zread — drives zwrite/output/cl_block
 *      and gives the decoder well-formed bodies with maxbits 9..16.
 *      A real temp file is needed because zopen(..., "w") opens with
 *      O_NOFOLLOW, which rejects the /proc/self/fd/<n> symlink.
 *
 * Note: zopen.c only speaks the LZW .Z format; gzip streams are
 * rejected at the magic check (gzip handling lives elsewhere), so a
 * gzip seed is included only to pin that reject path.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#include "../src.freebsd/compress/zopen.h"

static void
fuzz_read(const uint8_t *data, size_t size)
{
	char path[64];
	char buf[4096];
	FILE *f;
	int fd;

	fd = memfd_create("fuzz_zopen", 0);
	if (fd < 0)
		return;
	if (write(fd, data, size) != (ssize_t)size ||
	    lseek(fd, 0, SEEK_SET) < 0) {
		close(fd);
		return;
	}
	snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
	f = zopen(path, "r", 0, NULL);
	if (f != NULL) {
		while (fread(buf, 1, sizeof(buf), f) > 0)
			;
		fclose(f);
	}
	close(fd);
}

static void
fuzz_roundtrip(const uint8_t *data, size_t size)
{
	char path[] = "/tmp/fuzz_zopen_wXXXXXX";
	char buf[4096];
	FILE *f;
	int fd, bits;

	fd = mkstemp(path);
	if (fd < 0)
		return;
	(void)close(fd);
	/* Vary maxbits across the legal compress range. */
	bits = size > 0 ? 9 + (data[0] % 8) : 16;
	f = zopen(path, "w", bits, NULL);
	if (f != NULL) {
		if (size > 0)
			(void)fwrite(data, 1, size, f);
		if (fclose(f) == 0) {
			f = zopen(path, "r", 0, NULL);
			if (f != NULL) {
				while (fread(buf, 1, sizeof(buf), f) > 0)
					;
				fclose(f);
			}
		}
	}
	(void)unlink(path);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	fuzz_read(data, size);
	fuzz_roundtrip(data, size);
	return 0;
}
