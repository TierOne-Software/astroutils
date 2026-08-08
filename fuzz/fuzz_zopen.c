/*
 * fuzz_zopen.c — libFuzzer harness for the compress/zopen LZW
 * decoder (src.freebsd/compress/zopen.c: zopen/zread/getcode).
 * Historic CVE class: LZW table/stack overflows in *compress
 * decompressors fed crafted .Z streams.
 *
 * zopen(3) takes a pathname, so the fuzzer bytes are staged in a
 * memfd and handed to zopen() via /proc/self/fd/<n>.  Two paths are
 * exercised per input:
 *
 *   1. decode: zopen(memfd, "r") + fread() to EOF — the raw fuzzer
 *      bytes are treated as a .Z stream (bad magic, bogus n_bits,
 *      out-of-range codes, CLEAR floods all land here).
 *   2. roundtrip: zopen(memfd, "w") + fwrite of the fuzzer bytes,
 *      then re-read through zread — drives zwrite/output/cl_block
 *      and gives the decoder well-formed bodies with maxbits 9..16.
 *
 * Note: zopen.c only speaks the LZW .Z format; gzip streams are
 * rejected at the magic check (gzip handling lives elsewhere), so a
 * gzip seed is included only to pin that reject path.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
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
	f = zopen(path, "r", 0);
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
	char path[64];
	char buf[4096];
	FILE *f;
	int fd, bits;

	fd = memfd_create("fuzz_zopen_w", 0);
	if (fd < 0)
		return;
	snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
	/* Vary maxbits across the legal compress range. */
	bits = size > 0 ? 9 + (data[0] % 8) : 16;
	f = zopen(path, "w", bits);
	if (f != NULL) {
		if (size > 0)
			(void)fwrite(data, 1, size, f);
		if (fclose(f) == 0 && lseek(fd, 0, SEEK_SET) == 0) {
			f = zopen(path, "r", 0);
			if (f != NULL) {
				while (fread(buf, 1, sizeof(buf), f) > 0)
					;
				fclose(f);
			}
		}
	}
	close(fd);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	fuzz_read(data, size);
	fuzz_roundtrip(data, size);
	return 0;
}
