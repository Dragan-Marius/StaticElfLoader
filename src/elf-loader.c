// SPDX-License-Identifier: BSD-3-Clause

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <elf.h>
#include <string.h>
#include <stdint.h>
#include <sys/resource.h>
#include <sys/random.h>
// #include <math.h>
void *map_elf(const char *filename)
{
	// This part helps you store the content of the ELF file inside the buffer.
	struct stat st;
	void *file;
	int fd;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		perror("open");
		exit(1);
	}

	fstat(fd, &st);

	file = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (file == MAP_FAILED) {
		perror("mmap");
		close(fd);
		exit(1);
	}

	return file;
}

void load_and_run(const char *filename, int argc, char **argv, char **envp)
{
	// Contents of the ELF file are in the buffer: elf_contents[x] is the x-th byte of the ELF file.
	void *elf_contents = map_elf(filename);

	/**
	 * TODO: ELF Header Validation
	 * Validate ELF magic bytes - "Not a valid ELF file" + exit code 3 if invalid.
	 * Validate ELF class is 64-bit (ELFCLASS64) - "Not a 64-bit ELF" + exit code 4 if invalid.
	 */
	// char *str = (char *)elf_contents;
	// int i;
	Elf64_Ehdr *elf_magic = (Elf64_Ehdr *)elf_contents;
	int i;

	for (i = 0; i < SELFMAG; i++) {
		if (elf_magic->e_ident[i] != ELFMAG[i]) {
			fprintf(stderr, "Not a valid ELF file\n");
			exit(3);
		}
	}
	if (elf_magic->e_ident[EI_CLASS] != ELFCLASS64) {
		fprintf(stderr, "Not a 64-bit ELF\n");
		exit(4);
	}
	/**
	 * TODO: Load PT_LOAD segments
	 * For minimal syscall-only binaries.
	 * For each PT_LOAD segment:
	 * - Map the segments in memory. Permissions can be RWX for now.
	 */

	char *adresa_inceput_elf = (char *)elf_contents + elf_magic->e_phoff;
	Elf64_Phdr *phdr_load = (Elf64_Phdr *)adresa_inceput_elf;
	long dimensiunea_paginii = sysconf(_SC_PAGESIZE);

	for (i = 0; i < (int)elf_magic->e_phnum; i++) {
		if (phdr_load[i].p_type == PT_LOAD) {
			//in a cata pagina se afla phdr_load[i]
			unsigned long numarul_paginii = ((unsigned long)phdr_load[i].p_vaddr / dimensiunea_paginii);
			//de la ce adresa incepe pagina
			unsigned long start_index_pagina = (numarul_paginii)*dimensiunea_paginii;
			//diferenta de unde se afla phdr_load[i] si inceputul paginii
			unsigned long index_adresa = (unsigned long)phdr_load[i].p_vaddr - start_index_pagina;
			//lungimea zonei de la inceputul paginii pana la sfarsitul zonei de memorie phdr_load[i]
			unsigned long lungimea_zonei = index_adresa + (unsigned long)phdr_load[i].p_memsz;
			//gasim cel mai mic multiplu de dimensiune pagina care sa cuprinda lungimea zonei
			unsigned long lungime_mmap = ((lungimea_zonei / dimensiunea_paginii) + ((lungimea_zonei % dimensiunea_paginii) != 0)) * dimensiunea_paginii;
			void *phdr_mmap = mmap((void *)start_index_pagina, lungime_mmap, PROT_READ | PROT_EXEC | PROT_WRITE, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
			//pornin de la zona de unde am alocat memorie si o transformam intr un pointer valid
			char *destinatie = (char *)phdr_mmap + index_adresa;
			//de unde incep datele pentru phdr_load[i] in ELF
			char *sursa = (char *)elf_contents + phdr_load[i].p_offset;

			memcpy((void *)destinatie, (void *)sursa, phdr_load[i].p_filesz);
		}
	}
	/**
	 * TODO: Load Memory Regions with Correct Permissions
	 * For each PT_LOAD segment:
	 *	- Set memory permissions according to program header p_flags (PF_R, PF_W, PF_X).
	 *	- Use mprotect() or map with the correct permissions directly using mmap().
	 */
	for (i = 0; i < (int)elf_magic->e_phnum; i++) {
		if (phdr_load[i].p_type == PT_LOAD) {
			int permisiuni = 0;

			if (phdr_load[i].p_flags & PF_R)
				permisiuni = permisiuni | PROT_READ;
			if (phdr_load[i].p_flags & PF_W)
				permisiuni = permisiuni | PROT_WRITE;
			if (phdr_load[i].p_flags & PF_X)
				permisiuni = permisiuni | PROT_EXEC;
			unsigned long numarul_paginii = ((unsigned long)phdr_load[i].p_vaddr / dimensiunea_paginii);
			unsigned long start_index_pagina = (numarul_paginii)*dimensiunea_paginii;
			unsigned long index_adresa = (unsigned long)phdr_load[i].p_vaddr - start_index_pagina;
			unsigned long lungimea_zonei = index_adresa + (unsigned long)phdr_load[i].p_memsz;
			unsigned long lungime_mmap = ((lungimea_zonei / dimensiunea_paginii) + ((lungimea_zonei % dimensiunea_paginii) != 0)) * dimensiunea_paginii;

			mprotect((void *)start_index_pagina, lungime_mmap, permisiuni);
			// void * phdr_mmap=mmap((void*)start_index_pagina,lungime_mmap,PROT_READ|PROT_EXEC|PROT_WRITE,MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
			// char * destinatie=(char*)phdr_mmap+index_adresa;
			// char * sursa=(char*)elf_contents+phdr_load[i].p_offset;
			// void * copiere=mempcpy((void*)destinatie,(void *)sursa,phdr_load[i].p_memsz);
		}
	}

	/**
	 * TODO: Support Static Non-PIE Binaries with libc
	 * Must set up a valid process stack, including:
	 *	- argc, argv, envp
	 *	- auxv vector (with entries like AT_PHDR, AT_PHENT, AT_PHNUM, etc.)
	 * Note: Beware of the AT_RANDOM, AT_PHDR entries, the application will crash if you do not set them up properly.
	 *
	 */

	struct rlimit limite_resurse;
	unsigned long dimensiune_stiva = 0;

	if (getrlimit(RLIMIT_STACK, &limite_resurse) == 0)
		dimensiune_stiva = limite_resurse.rlim_cur;
	void *stiva = mmap(NULL, dimensiune_stiva, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	stiva = (char *)stiva + dimensiune_stiva;

	int env_count = 0;

	for (; envp[env_count] != NULL; env_count++)
		;

	Elf64_auxv_t auxv[16];

	i = 0;
	auxv[i].a_type = AT_IGNORE;
	auxv[i].a_un.a_val = 0;
	i++;

	auxv[i].a_type = AT_EXECFD;
	auxv[i].a_un.a_val = 0;
	i++;

	auxv[i].a_type = AT_PHDR;
	int j;

	for (j = 0; j < (int)elf_magic->e_phnum; j++) {
		if (phdr_load[j].p_type == PT_PHDR) {
			auxv[i].a_un.a_val = (unsigned long)phdr_load[j].p_vaddr;
			break;
		}
	}
	if (j == (int)elf_magic->e_phnum)
		auxv[i].a_un.a_val = 0;
	i++;

	auxv[i].a_type = AT_PHENT;
	auxv[i].a_un.a_val = (unsigned long)elf_magic->e_phentsize;
	i++;

	auxv[i].a_type = AT_PHNUM;
	auxv[i].a_un.a_val = (unsigned long)elf_magic->e_phnum;
	i++;

	auxv[i].a_type = AT_PAGESZ;
	auxv[i].a_un.a_val = (unsigned long)dimensiunea_paginii;
	i++;

	auxv[i].a_type = AT_BASE;
	auxv[i].a_un.a_val = 0;
	i++;

	auxv[i].a_type = AT_ENTRY;
	auxv[i].a_un.a_val = (unsigned long)elf_magic->e_entry;
	i++;

	auxv[i].a_type = AT_NOTELF;
	for (j = 0; j < SELFMAG; j++) {
		if (elf_magic->e_ident[j] != ELFMAG[j])
			auxv[i].a_un.a_val = 0;
	}
	if (j == SELFMAG)
		auxv[i].a_un.a_val = 1;
	i++;

	auxv[i].a_type = AT_UID;
	auxv[i].a_un.a_val = getuid();
	i++;

	auxv[i].a_type = AT_EUID;
	auxv[i].a_un.a_val = geteuid();
	i++;

	auxv[i].a_type = AT_GID;
	auxv[i].a_un.a_val = getgid();
	i++;

	auxv[i].a_type = AT_EGID;
	auxv[i].a_un.a_val = getegid();
	i++;

	auxv[i].a_type = AT_CLKTCK;
	auxv[i].a_un.a_val = sysconf(_SC_CLK_TCK);
	i++;

	auxv[i].a_type = AT_RANDOM;
	unsigned char random_bytes[16];

	getrandom(random_bytes, 16, 0);
	auxv[i].a_un.a_val = (unsigned long)random_bytes;
	i++;

	auxv[i].a_type = AT_NULL;
	auxv[i].a_un.a_val = 0;
	i++;

	stiva = (char *)stiva - i * sizeof(Elf64_auxv_t);
	memcpy(stiva, auxv, i * sizeof(Elf64_auxv_t));

	void *pointer_null = NULL;

	stiva = stiva - sizeof(void *);
	memcpy(stiva, &pointer_null, sizeof(void *));

	for (i = env_count - 1; i >= 0; i--) {
		stiva = (char *)stiva - sizeof(char *);
		memcpy(stiva, &envp[i], sizeof(char *));
	}

	stiva = stiva - sizeof(void *);
	memcpy(stiva, &pointer_null, sizeof(void *));
	for (i = argc - 1; i >= 0; i--) {
		stiva = (char *)stiva - sizeof(char *);
		memcpy(stiva, &argv[i], sizeof(char *));
	}

	stiva = (char *)stiva - sizeof(int *);
	memcpy(stiva, &argc, sizeof(int *));
	void *sp = stiva;

	/**
	 *
	 * TODO: Support Static PIE Executables
	 * Map PT_LOAD segments at a random load base.
	 * Adjust virtual addresses of segments and entry point by load_base.
	 * Stack setup (argc, argv, envp, auxv) same as above.
	 */
	// TODO: Set the entry point and the stack pointer
	void (*entry)() = (void (*)(void))elf_magic->e_entry;

	// Transfer control
	__asm__ __volatile__(
		"mov %0, %%rsp\n"
		"xor %%rbp, %%rbp\n"
		"jmp *%1\n"
		:
		: "r"(sp), "r"(entry)
		: "memory");
}

int main(int argc, char **argv, char **envp)
{
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <static-elf-binary>\n", argv[0]);
		exit(1);
	}

	load_and_run(argv[1], argc - 1, &argv[1], envp);
	return 0;
}
