// SPDX License identifer: BSD-3-Clause
// Copyright 2022 - 2022, Eishun Kondoh<dreamdiagnosis@gmail.com>

#include <ctype.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <errno.h>
#include <fts.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>

#define MAX_ARG_POS 5
#define FUNC_LIST_FILE "/tmp/vrftrace_func_list.txt"

const char *btf_str_by_offset_from_type(const struct btf *btf,
					const struct btf_type *t)
{
	return btf__str_by_offset(btf, t->name_off);
}

int btf_find_pos(const char *st_name, const struct btf *btf,
		 const char *filename)
{
	const struct btf_type *func_proto, *t;
	const struct btf_param *params;
	const char *arg_st_name, *func_name;
	FILE *fp = fopen(filename, "a");

	for (uint32_t id = 0; (t = btf__type_by_id(btf, id)); id++) {
		int pos = 0;

		if (!btf_is_func(t))
			continue;

		func_name = btf__str_by_offset(btf, t->name_off);
		func_proto = btf__type_by_id(btf, t->type);
		params = btf_params(func_proto);

		for (uint16_t i = 0; i < btf_vlen(func_proto); i++) {
			t = btf__type_by_id(btf, params[i].type);

			while (btf_is_mod(t))
				t = btf__type_by_id(btf, t->type);

			if (btf_is_struct(t) || btf_is_union(t))
				break;
		}

		for (uint16_t i = 0;
		     i < btf_vlen(func_proto) && i < MAX_ARG_POS - 1; i++) {
			t = btf__type_by_id(btf, params[i].type);

			if (!btf_is_ptr(t))
				continue;

			t = btf__type_by_id(btf, t->type);
			arg_st_name = btf__str_by_offset(btf, t->name_off);
			if (strcmp(st_name, arg_st_name) != 0)
				continue;

			pos = i + 1;
			break;
		}

		if (pos > 0)
			fprintf(fp, "%s %d\n", func_name, pos);
	}

	fclose(fp);
	return 0;
}
