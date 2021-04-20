/*

    Protcheck 1.0.1 - @lockedbyte (https://github.com/lockedbyte/protcheck)
    
        A C utility to check an ELF binary protections parsing the ELF directly instead of using intermediate programs like readelf or grep.
        
*/

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>

#include "elf_defines.h" /* ELF Format defines */
#include "protcheck.h" /* needed headers */
#include "protcheck_x86.h" /* needed headers */

// -- functions --
int load_libc_x86(char *libc_path);
int check_canary_x86(void);
int is_pointer_valid_x86(void *p);
int check_RELRO_x86(void);
int check_NX_x86(void);
int check_FORTIFY_x86(void);
int check_PIE_x86(void);
int check_ELF_x86(void);
char *get_arch_x86(void);
char *get_bits_x86(void);
void check_rwx_segments_x86(void);
void check_dangerous_imports_x86(void);
int launch_checks_x86(void *memchunk, char *file_path, char *libc_path, int global_sz);
// -------------

Elf32_Ehdr *elf_ehdr_x86 = NULL;
Elf32_Shdr *shdr_x86 = NULL;
Elf32_Phdr *phdr_x86 = NULL;

Elf32_Ehdr *libc_ehdr_x86 = NULL;
Elf32_Shdr *libc_shdr_x86 = NULL;
Elf32_Phdr *libc_phdr_x86 = NULL;

int global_size_x86 = 0;

int libc_size_x86 = 0;

void *sname_x86 = NULL;
void *base_x86 = 0;

int sname_prox_size_x86 = 512;

void *libc_sname_x86 = NULL;
void *libc_base_x86 = 0;

int fortify_flag_x86 = 1;

int load_libc_x86(char *libc_path) {

    void *Elf32_Ehdr_chunk = NULL;
    void *memchunk = NULL;
    int fd = 0;
    struct stat sb;
    
    if(libc_path == NULL)
        fd = open(RELATIVE_PTH_x86, O_RDONLY);
    else
        fd = open(libc_path, O_RDONLY);
        
    if(fd < 0) {
        if(libc_path != NULL) {
            printf("\033[1;31m[-] Specified libc path not found. Skipping FORTIFY checks then...\033[0m\n\n");
            fortify_flag_x86 = 0;
        } else {
        
            fd = open(LIBC_PATH_x86, O_RDONLY);

            if(fd < 0) {
                printf("\033[1;31m[-] '%s' or '%s' not found. Skipping FORTIFY checks then...\033[0m\n\n", LIBC_PATH_x86, RELATIVE_PTH_x86);
                fortify_flag_x86 = 0;
            }
        
        }
    }
    
    if(fortify_flag_x86) {
    
        fstat(fd, &sb);

        memchunk = mmap(NULL, sb.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

        if(memchunk == MAP_FAILED) {
            printf("\033[1;31m[-] mmap failed. Skipping FORTIFY checks then...\033[0m\n\n");
            fortify_flag_x86 = 0;
            
            return 0;  
        }

        libc_size_x86 = sb.st_size;

        Elf32_Ehdr *a0 = (Elf32_Ehdr *)memchunk;	
        Elf64_Ehdr *a1 = (Elf64_Ehdr *)memchunk;
        
        if(a0->e_ident[BIT_INDENT_INDEX] == ELFCLASS64) {
            printf("\033[1;31m[-] The loaded libc architecture is wrong. Skipping FORTIFY checks then...\033[0m\n\n");
            fortify_flag_x86 = 0;
            return 0;
        } else {
            if(a1->e_ident[BIT_INDENT_INDEX] == ELFCLASS64) {
                printf("\033[1;31m[-] The loaded libc architecture is wrong. Skipping FORTIFY checks then...\033[0m\n\n");
                fortify_flag_x86 = 0;
                return 0;
            }
        }
        
        libc_base_x86 = (void *)memchunk;

        Elf32_Ehdr_chunk = mmap(NULL, sizeof(Elf32_Ehdr), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        
        if(Elf32_Ehdr_chunk == MAP_FAILED) {
            printf("\033[1;31m[-] mmap failed. Skipping FORTIFY checks then...\033[0m\n\n");
            fortify_flag_x86 = 0;
            
            return 0;  
        }

        if(sb.st_size < sizeof(Elf32_Ehdr)) {
            printf("\033[1;31m[-] Specified libc is wrong. Skipping FORTIFY checks then...\033[0m\n\n");
            fortify_flag_x86 = 0;
            
            return 0;
            
        }
        
        memcpy((void *)Elf32_Ehdr_chunk, memchunk, sizeof(Elf32_Ehdr));
        
	    libc_ehdr_x86 = (Elf32_Ehdr *)Elf32_Ehdr_chunk;

	    for(int i = 0 ; i < 4 ; i++) {
	        if(libc_ehdr_x86->e_ident[i] != ELFMAG[i]) {
	            printf("\033[1;31m[-] libc corrupted or wrong. Skipping FORTIFY checks then...\033[0m\n\n");
	            fortify_flag_x86 = 0;
	            
	            return 0;
	        }
	    }
	    

        if((libc_base_x86 + libc_ehdr_x86->e_shoff) <= (libc_base_x86 + libc_size_x86 - sizeof(Elf32_Shdr))) 
            libc_shdr_x86 = (Elf32_Shdr *)(libc_base_x86 + libc_ehdr_x86->e_shoff);
        else
            mem_error();

        if((libc_base_x86 + libc_ehdr_x86->e_phoff) <= (libc_base_x86 + libc_size_x86 - sizeof(Elf32_Ehdr))) 
            libc_phdr_x86 = (Elf32_Phdr *)(libc_base_x86 + libc_ehdr_x86->e_phoff);
        else
            mem_error();

        if(libc_ehdr_x86->e_shstrndx > sizeof(Elf32_Shdr))
            mem_error();

        if((libc_base_x86 + libc_shdr_x86[libc_ehdr_x86->e_shstrndx].sh_offset) <= (libc_base_x86 + libc_size_x86 - sizeof(Elf32_Shdr))) 
            libc_sname_x86 = (void *)(libc_base_x86 + libc_shdr_x86[libc_ehdr_x86->e_shstrndx].sh_offset);
        else
            mem_error();

	}
	
	return 1;
	
}

int is_pointer_valid_x86(void *p) {
    size_t page_size = sysconf(_SC_PAGESIZE);
    void *basex = (void *)((((size_t)p) / page_size) * page_size);
    return msync(basex, page_size, MS_ASYNC) == 0;
}

int check_canary_x86(void) {

    if(shdr_x86 + elf_ehdr_x86->e_phnum > shdr_x86 + sizeof(Elf32_Shdr))
        mem_error();

    for (int i = 0; i < elf_ehdr_x86->e_phnum; i++) {

        if(shdr_x86[i].sh_type == SHT_DYNSYM) {

            Elf32_Sym *sym = (Elf32_Sym *)(base_x86 + shdr_x86[i].sh_offset);
            int num = shdr_x86[i].sh_size / shdr_x86[i].sh_entsize;
            void *sdata = (void *)base_x86 + shdr_x86[shdr_x86[i].sh_link].sh_offset;

            for(int j = 0; j < num; j++) {
                
                if(sdata + sym[j].st_name == NULL || 
                   !is_pointer_valid_x86(sdata + sym[j].st_name))
                    continue;
                    
                if(strcmp((char *)(sdata + sym[j].st_name), CANARY_CLUE_1) == 0 || 
                    strcmp((char *)(sdata + sym[j].st_name), CANARY_CLUE_2) == 0)
                    return CANARY_TRUE;
                    
            }
        }
    }
	    
    return CANARY_FALSE;
    
}

int check_RELRO_x86(void) {
    
    int relro = 0;
    int bind = 0;

    if(phdr_x86 + elf_ehdr_x86->e_phnum > phdr_x86 + sizeof(Elf32_Phdr))
        mem_error();

    if(shdr_x86 + elf_ehdr_x86->e_shnum > shdr_x86 + sizeof(Elf32_Shdr))
        mem_error();

	for (int i = 0; i < elf_ehdr_x86->e_phnum; i++) {
	    if(phdr_x86[i].p_type == PT_GNU_RELRO)
		        relro = 1;
    }
		        
    for(int i = 0; i < elf_ehdr_x86->e_shnum; i++) {
        if(shdr_x86[i].sh_type == SHT_DYNAMIC) {
        
		    Elf32_Dyn *dyn = (Elf32_Dyn *)(base_x86 + shdr_x86[i].sh_offset);
		    int num = shdr_x86[i].sh_size / shdr_x86[i].sh_entsize;
		    //void *sdata = (void *)base_x86 + shdr_x86[shdr_x86[i].sh_link].sh_offset;
            
            for(int j = 0; j < num; j++) {
                if(dyn[j].d_tag == DT_FLAGS) 
                    if(CHECK_BIT(dyn[j].d_un.d_val, BIND_NOW_BIT_POS))
                        bind = 1;
            }
        }
    
    }
    
    if(!relro)
        return RELRO_FALSE;
    else if(relro && !bind)
        return RELRO_PARTIAL;
    else if(relro && bind)
        return RELRO_FULL;
    
    return -1;
}

int check_NX_x86(void) {

    if(phdr_x86 + elf_ehdr_x86->e_phnum > phdr_x86 + sizeof(Elf32_Phdr))
        mem_error();

	for (int i = 0; i < elf_ehdr_x86->e_phnum; i++)
	    if(phdr_x86[i].p_type == PT_GNU_STACK && 
	        phdr_x86[i].p_flags == RWE_PROT)
		        return NX_FALSE;
        return NX_TRUE;

}

int check_FORTIFY_x86(void) {
    
    char buf[256];
    
    memset(buf, '\0', sizeof(buf));

    if(shdr_x86 + elf_ehdr_x86->e_phnum > shdr_x86 + sizeof(Elf32_Shdr))
        mem_error();

    for (int i = 0; i < elf_ehdr_x86->e_phnum; i++) {
        for (int x = 0; x < libc_ehdr_x86->e_phnum; x++) {
            
            if(shdr_x86[i].sh_type == SHT_DYNSYM && libc_shdr_x86[x].sh_type == SHT_DYNSYM) {

                Elf32_Sym *sym = (Elf32_Sym *)(base_x86 + shdr_x86[i].sh_offset);
                int num = shdr_x86[i].sh_size / shdr_x86[i].sh_entsize;
                void *sdata = (void *)base_x86 + shdr_x86[shdr_x86[i].sh_link].sh_offset;

                Elf32_Sym *libc_sym = (Elf32_Sym *)(libc_base_x86 + libc_shdr_x86[x].sh_offset);
                int libc_num = libc_shdr_x86[i].sh_size / libc_shdr_x86[x].sh_entsize;
                void *libc_sdata = (void *)libc_base_x86 + libc_shdr_x86[libc_shdr_x86[x].sh_link].sh_offset;
                
                for(int j = 0; j < num; j++) {
                    for(int k = 0; k < libc_num; k++) {
                    
                        memset(buf, '\0', sizeof(buf));

                        if(sdata + sym[j].st_name == NULL || 
                           !is_pointer_valid_x86(sdata + sym[j].st_name))
                            continue;

                        if(libc_sdata + libc_sym[k].st_name == NULL || 
                           !is_pointer_valid_x86(libc_sdata + libc_sym[k].st_name))
                            continue;
                             
                        snprintf(buf, sizeof(buf)-1, "__%s_chk", (char *)(libc_sdata + libc_sym[k].st_name));
                        
                        if(strcmp(buf, (char *)(sdata + sym[j].st_name)) == 0)
                            return FORTIFY_TRUE;
                    }
                }
            }
        }
    }
	    
    return FORTIFY_FALSE;
    
}

int check_PIE_x86(void) {
    
    if(phdr_x86 + elf_ehdr_x86->e_phnum > phdr_x86 + sizeof(Elf32_Phdr))
        mem_error();
    
    if(elf_ehdr_x86->e_type == ET_DYN)
        return 0;
    else {
	    for (int i = 0; i < elf_ehdr_x86->e_phnum; i++)
	        if(phdr_x86[i].p_type == PT_LOAD)
		            return phdr_x86[i].p_vaddr;
        return 0x1;
    }
}

void mem_error(void) {
    printf("\033[1;31m[-] A memory error has ocurred!\033[0m\n");
    exit(-1);
}

int check_ELF_x86(void) {

    for(int i = 0 ; i < 4 ; i++)
        if(elf_ehdr_x86->e_ident[i] != ELFMAG[i])
            return 0;

    if((base_x86 + elf_ehdr_x86->e_shoff) <= (base_x86 + global_size_x86 - sizeof(Elf32_Shdr)))
	   shdr_x86 = (Elf32_Shdr *)(base_x86 + elf_ehdr_x86->e_shoff);
    else
        mem_error();

    if((base_x86 + elf_ehdr_x86->e_phoff) <= (base_x86 + global_size_x86 - sizeof(Elf32_Phdr)))
       phdr_x86 = (Elf32_Phdr *)(base_x86 + elf_ehdr_x86->e_phoff);
    else
        mem_error();

    if(elf_ehdr_x86->e_shstrndx > sizeof(Elf32_Shdr))
        mem_error();

    if((base_x86 + shdr_x86[elf_ehdr_x86->e_shstrndx].sh_offset) <= (base_x86 + global_size_x86 - sname_prox_size_x86))
       sname_x86 = (void *)(base_x86 + shdr_x86[elf_ehdr_x86->e_shstrndx].sh_offset);
    else
        mem_error();

	return 1;

}


char *get_arch_x86(void) {

	if(elf_ehdr_x86->e_machine == EM_386)
		return EM_386_STR;
	else if(elf_ehdr_x86->e_machine == EM_860)
	    return EM_860_STR;
	else if(elf_ehdr_x86->e_machine == EM_X86_64)
		return EM_X86_64_STR;
	else if(elf_ehdr_x86->e_machine == EM_ARM)
	    return EM_ARM_STR;
	else
		return UNKNOWN_STR;

}

char *get_bits_x86(void) {

	if(elf_ehdr_x86->e_ident[BIT_INDENT_INDEX] == ELFCLASS32)
		return ELF_32_T_STR;
	else if(elf_ehdr_x86->e_ident[BIT_INDENT_INDEX] == ELFCLASS64)
		return ELF_64_T_STR;
	else
		return ELF_UNK_T_STR;
		
}

void check_rwx_segments_x86(void) {
    int found = 0;
    
    if(phdr_x86 + elf_ehdr_x86->e_phnum > phdr_x86 + sizeof(Elf32_Phdr))
        mem_error();

	for (int i = 0; i < elf_ehdr_x86->e_phnum; i++)
	    if(phdr_x86[i].p_flags == RWE_PROT) {
	        if(!found)
		        printf("  RWX:\t\t\033[1;31mHas RWX Segments\033[0m\n");
		}
}

void check_dangerous_imports_x86(void) {
    // gets()
    
    int found = 0;

    if(shdr_x86 + elf_ehdr_x86->e_phnum  > shdr_x86 + sizeof(Elf32_Shdr))
        mem_error();
    
    for (int i = 0; i < elf_ehdr_x86->e_phnum; i++) {

        if(shdr_x86[i].sh_type == SHT_DYNSYM) {

            Elf32_Sym *sym = (Elf32_Sym *)(base_x86 + shdr_x86[i].sh_offset);
            int num = shdr_x86[i].sh_size / shdr_x86[i].sh_entsize;
            void *sdata = (void *)base_x86 + shdr_x86[shdr_x86[i].sh_link].sh_offset;

            for(int j = 0; j < num; j++) {
                
                if(sdata + sym[j].st_name == NULL || 
                   !is_pointer_valid_x86(sdata + sym[j].st_name))
                    continue;
                
                if(strcmp((char *)(sdata + sym[j].st_name), "gets") == 0)
                    goto FOUND_X;
                else
                    continue;
                
                FOUND_X:

                    if(!found)
                        printf("\n  \033[1;34m[=]\033[0m Found dangerous imports: \n");
                    found++;
                    printf("    \033[1;32m[+]\033[0m Imported function: %s\n", (char *)(sdata + sym[j].st_name));

            }
        }
    }
}

void check_interesting_imports_x86(void) {

    // system, mprotect, mmap, execve, __libc_system, fexecve, mmap64, __mmap, __mprotect, pkey_mprotect, syscall, dup2

    int found = 0;

    if(shdr_x86 + elf_ehdr_x86->e_phnum > shdr_x86 + sizeof(Elf32_Shdr))
        mem_error();
    
    for (int i = 0; i < elf_ehdr_x86->e_phnum; i++) {

        if(shdr_x86[i].sh_type == SHT_DYNSYM) {

            Elf32_Sym *sym = (Elf32_Sym *)(base_x86 + shdr_x86[i].sh_offset);
            int num = shdr_x86[i].sh_size / shdr_x86[i].sh_entsize;
            void *sdata = (void *)base_x86 + shdr_x86[shdr_x86[i].sh_link].sh_offset;

            for(int j = 0; j < num; j++) {
                
                if(sdata + sym[j].st_name == NULL || 
                   !is_pointer_valid_x86(sdata + sym[j].st_name))
                    continue;
                
                if(strcmp((char *)(sdata + sym[j].st_name), "system") == 0)
                    goto FOUND_X;
                else if(strcmp((char *)(sdata + sym[j].st_name), "mmap") == 0)
                    goto FOUND_X;
                else if(strcmp((char *)(sdata + sym[j].st_name), "__mmap") == 0)
                    goto FOUND_X;
                else if(strcmp((char *)(sdata + sym[j].st_name), "mmap64") == 0)
                    goto FOUND_X;
                else if(strcmp((char *)(sdata + sym[j].st_name), "mprotect") == 0)
                    goto FOUND_X;
                else if(strcmp((char *)(sdata + sym[j].st_name), "__mprotect") == 0)
                    goto FOUND_X;
                else if(strcmp((char *)(sdata + sym[j].st_name), "pkey_mprotect") == 0)
                    goto FOUND_X;
                else if(strcmp((char *)(sdata + sym[j].st_name), "syscall") == 0)
                    goto FOUND_X;
                else if(strcmp((char *)(sdata + sym[j].st_name), "dup2") == 0)
                    goto FOUND_X;
                else if(strcmp((char *)(sdata + sym[j].st_name), "execve") == 0)
                    goto FOUND_X;
                else if(strcmp((char *)(sdata + sym[j].st_name), "fexecve") == 0)
                    goto FOUND_X;
                else if(strcmp((char *)(sdata + sym[j].st_name), "__libc_system") == 0)
                    goto FOUND_X;
                else
                    continue;
                
                FOUND_X:

                    if(!found)
                        printf("\n  \033[1;34m[=]\033[0m Found interesting imports: \n");
                    found++;
                    printf("    \033[1;32m[+]\033[0m Imported function: %s\n", (char *)(sdata + sym[j].st_name));

            }
        }
    }
}

int launch_checks_x86(void *memchunk, char *file_path, char *libc_path, int global_sz) {
    
    int relro = 0;
    int base_addr = 0;
    char full_arch[50];
    
    memset(full_arch, '\0', sizeof(full_arch));

    global_size_x86 = global_sz;
    
    base_x86 = (void *)memchunk;
    
    void *Elf32_Ehdr_chunk = NULL;
	
    Elf32_Ehdr_chunk = mmap(NULL, sizeof(Elf32_Ehdr), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    
    if(Elf32_Ehdr_chunk == MAP_FAILED) return -1;
    
    memcpy((void *)Elf32_Ehdr_chunk, memchunk, sizeof(Elf32_Ehdr));
    
	elf_ehdr_x86 = (Elf32_Ehdr *)Elf32_Ehdr_chunk;
    
    if(!check_ELF_x86()) {
        printf("\033[1;31m[-] The file is corrupted or not an ELF file.\033[0m\n");
        return 0;
    }

    snprintf(full_arch, sizeof(full_arch)-1, "%s - %s", get_bits_x86(), get_arch_x86());
    
    if(fortify_flag_x86)
        load_libc_x86(libc_path);
    
    printf("\033[1;34m[*]\033[0m '%s\033[0m'\033[0m\n", file_path);
    printf("  Arch: \t%s\033[0m\n", full_arch);
    
    
    relro = check_RELRO_x86();
    
    printf("  RELRO: ");
	if(relro == RELRO_FALSE)
	    printf("\t\033[0;31mNo RELRO\033[0m\n");
	else if(relro == RELRO_FULL)
	    printf("\t\033[0;32mFull RELRO\033[0m\n");
	else
	    printf("\t\033[0;33mPartial RELRO\033[0m\n");
	
	printf("  NX: ");
	if(check_NX_x86())
	    printf("\t\t\033[0;32mNX Enabled\033[0m\n");
	else
	    printf("\t\t\033[0;31mNX Disabled\033[0m\n");
	    
    printf("  Stack: ");    
	if(check_canary_x86())
	    printf("\t\033[0;32mCanary found\033[0m\n");
	else
	    printf("\t\033[0;31mCanary not found\033[0m\n");
	    
    printf("  PIE: ");
    base_addr = check_PIE_x86();
	if(base_addr == 0)
	    printf("\t\t\033[0;32mPIE Enabled\033[0m\n");
	else if(base_addr == 0x1)
        printf("\t\t\033[0;31mNo PIE\033[0m\n");
    else
	    printf("\t\t\033[0;31mNo PIE (0x%x)\033[0m\n", base_addr);

    printf("  FORTIFY: ");
    if(fortify_flag_x86) {
	    if(check_FORTIFY_x86())
	        printf("\t\033[0;32mFORTIFY Detected\033[0m\n");
	    else
	        printf("\t\033[0;31mFORTIFY not found\033[0m\n");
	} else {
	    printf("\t\033[0;93mSkipped\033[0m\n");
	}
	
    check_rwx_segments_x86();
    check_dangerous_imports_x86();
    check_interesting_imports_x86();
	     
	return 0;

}
