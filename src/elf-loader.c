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

/*Function to map the ELF file into memory for initial parsing*/
void *map_elf(const char *filename)
{
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
	void *elf_contents = map_elf(filename);
	/*ELF Header Validation*/
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

	/*Process Program Headers and Map PT_LOAD Segments*/
	char *elf_address = (char *)elf_contents + elf_magic->e_phoff;
	Elf64_Phdr *phdr_table = (Elf64_Phdr *)elf_address;
	long page_size = sysconf(_SC_PAGESIZE);

	for (i = 0; i < (int)elf_magic->e_phnum; i++) {
		if (phdr_table[i].p_type == PT_LOAD) {
			/*Calculate page alignment and mapping size*/
			unsigned long page_num = ((unsigned long)phdr_table[i].p_vaddr / page_size);
			unsigned long page_start = (page_num)*page_size;
			unsigned long addr_offset = (unsigned long)phdr_table[i].p_vaddr - page_start;
			unsigned long total_len = addr_offset + (unsigned long)phdr_table[i].p_memsz;
			unsigned long mmap_len = ((total_len / page_size) + ((total_len % page_size) != 0)) * page_size;
			/*Map memory with broad permission initially for data copying*/
			void *segment_mmap = mmap((void *)page_start, mmap_len, PROT_READ | PROT_EXEC | PROT_WRITE, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
			char *dest = (char *)segment_mmap + addr_offset;
			char *src = (char *)elf_contents + phdr_table[i].p_offset;
			/*Copy content from file to virtual memory*/
			memcpy((void *)dest, (void *)src, phdr_table[i].p_filesz);
		}
	}

	for (i = 0; i < (int)elf_magic->e_phnum; i++) {
		if (phdr_table[i].p_type == PT_LOAD) {
			int perms = 0;
			/*Apply Fine-grained Memory Permissions*/
			if (phdr_table[i].p_flags & PF_R)
				perms = perms | PROT_READ;
			if (phdr_table[i].p_flags & PF_W)
				perms = perms | PROT_WRITE;
			if (phdr_table[i].p_flags & PF_X)
				perms = perms | PROT_EXEC;
			unsigned long page_num = ((unsigned long)phdr_table[i].p_vaddr / page_size);
			unsigned long page_start = (page_num)*page_size;
			unsigned long addr_offset = (unsigned long)phdr_table[i].p_vaddr - page_start;
			unsigned long total_len = addr_offset + (unsigned long)phdr_table[i].p_memsz;
			unsigned long mmap_len = ((total_len / page_size) + ((total_len % page_size) != 0)) * page_size;

			mprotect((void *)page_start, mmap_len, perms);
		}
	}
	/*Prepare Process stack(argc,argv,envp,auxv)*/
	struct rlimit rlim;
	unsigned long stack_size = 0;

	if (getrlimit(RLIMIT_STACK, &rlim) == 0)
		stack_size = rlim.rlim_cur;
	void *stack= mmap(NULL, stack_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	stack= (char *)stack+ stack_size;

	int env_count = 0;

	for (; envp[env_count] != NULL; env_count++)
		;
	/*Construct Auxiliary Vector(auxv)*/
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
	/*Find PT_PHDR for the auxiliary vector*/
	for (j = 0; j < (int)elf_magic->e_phnum; j++) {
		if (phdr_table[j].p_type == PT_PHDR) {
			auxv[i].a_un.a_val = (unsigned long)phdr_table[j].p_vaddr;
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
	auxv[i].a_un.a_val = (unsigned long)page_size;
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

	stack= (char *)stack- i * sizeof(Elf64_auxv_t);
	memcpy(stack, auxv, i * sizeof(Elf64_auxv_t));

	void *pointer_null = NULL;

	stack= stack- sizeof(void *);
	memcpy(stack, &pointer_null, sizeof(void *));

	for (i = env_count - 1; i >= 0; i--) {
		stack= (char *)stack- sizeof(char *);
		memcpy(stack, &envp[i], sizeof(char *));
	}

	stack= stack- sizeof(void *);
	memcpy(stack, &pointer_null, sizeof(void *));
	for (i = argc - 1; i >= 0; i--) {
		stack= (char *)stack- sizeof(char *);
		memcpy(stack, &argv[i], sizeof(char *));
	}

	stack= (char *)stack- sizeof(int *);
	memcpy(stack, &argc, sizeof(int *));
	void *sp = stack;

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
