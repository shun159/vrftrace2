// SPDX License identifer: BSD-3-Clause
// Copyright 2022 - 2022, Eishun Kondoh<dreamdiagnosis@gmail.com>

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "vrouter.bpf.h"
#include "vrftrace_kprobe.bpf.o.h"

int create_tmpfile_from_image(int *fdp, char **namep, uint8_t *image,
			      size_t image_size)
{
	int fd;
	char *name;

	name = strdup("/tmp/vrft_XXXXXX");
	if (name == NULL) {
		fprintf(stderr, "Failed to allocate memory for tmpfile name\n");
		return -1;
	}

	fd = mkstemp(name);
	if (fd == -1) {
		fprintf(stderr, "Failed to create tmpfile\n");
		return -1;
	}

	if (write(fd, image, image_size) == -1) {
		fprintf(stderr, "Failed to write image to tmpfile\n");
		goto err0;
	}

	*fdp = fd;
	*namep = name;

	return 0;

err0:
	close(fd);
	unlink(name);
	return -1;
}

int get_vrouter_btf_image(unsigned char **imagep, unsigned int *image_sizep)
{
	// Currently, the vrouter version embedded in this program is R2011.L4 only.
	*imagep = bpf_btf_vrouter_r2011L4_btf;
	*image_sizep = bpf_btf_vrouter_r2011L4_btf_len;

	return 0;
}

int get_kprobe_mod_image(unsigned char **imagep, unsigned int *image_sizep)
{
	*imagep = dist_vrftrace_kprobe_bpf_o;
	*image_sizep = dist_vrftrace_kprobe_bpf_o_len;

	return 0;
}

int do_link(char **namep, unsigned char *image, unsigned int image_size)
{
	int error = -1, fd;

	error = create_tmpfile_from_image(&fd, namep, image, image_size);
	if (error == -1) {
		fprintf(stderr,
			"create_tmpfile_from_image for target image failed\n");
		return -1;
	}

	return 0;
}

int deploy_vrouter_btf(char **namep)
{
	int error;
	unsigned char *target_image;
	unsigned int target_image_size;

	error = get_vrouter_btf_image(&target_image, &target_image_size);
	if (error != 0) {
		fprintf(stderr, "get_target_image failed\n");
		return -1;
	}

	error = do_link(namep, target_image, target_image_size);
	if (error == -1) {
		fprintf(stderr, "do_link failed\n");
		return -1;
	}

	return 0;
}

int deploy_kprobe_module(char **namep)
{
	int error;
	unsigned char *target_image;
	unsigned int target_image_size;

	error = get_kprobe_mod_image(&target_image, &target_image_size);
	if (error != 0) {
		fprintf(stderr, "get_target_image failed\n");
		return -1;
	}

	error = do_link(namep, target_image, target_image_size);
	if (error == -1) {
		fprintf(stderr, "do_link failed\n");
		return -1;
	}

	return 0;
}
