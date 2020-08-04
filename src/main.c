/*

    Protcheck 1.0.0 - @lockedbyte (https://github.com/lockedbyte/protcheck)
    
        A C utility to check an ELF binary protections parsing the ELF directly instead of using intermediate programs like readelf or grep.
        
*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <signal.h>
#include <unistd.h>

#include "protcheck_x86.h"
#include "protcheck_x86_64.h"
#include "elf_defines.h"

#define MAX_PATH_SIZE 256

int precheck_bits(char *loaded) {

    Elf32_Ehdr *a0 = (Elf32_Ehdr *)loaded;	
    Elf64_Ehdr *a1 = (Elf64_Ehdr *)loaded;
    
    if(a0->e_ident[BIT_INDENT_INDEX] == ELFCLASS32)
        return ELFCLASS32;
    else if(a0->e_ident[BIT_INDENT_INDEX] == ELFCLASS64)
        return ELFCLASS64;
    else {
        if(a1->e_ident[BIT_INDENT_INDEX] == ELFCLASS32)
            return ELFCLASS32;
        else if(a1->e_ident[BIT_INDENT_INDEX] == ELFCLASS64)
            return ELFCLASS64;
        else
            exit(0);
    }
}

int is_directory(const char *path) {
   struct stat statbuf;
   if (stat(path, &statbuf) != 0)
       return 0;
   return S_ISDIR(statbuf.st_mode);
}


int main(int argc, char *argv[]) {

    const char *memblock;
    int fd;
    struct stat sb;
    
    char file_path[MAX_PATH_SIZE];
    
    memset(file_path, '\0', sizeof(file_path));
    
    puts("\n\033[1;35m - [ ProtCheck ] -\033[0m\n ");
    if(argc < 2) {
        printf("\033[0;93m[%%] Common usage: %s <file path>\n[%%] Remote system usage: %s <file path> <libc path>\n\n\033[0m", argv[0], argv[0]);
        exit(0);
    }
    
    if(strlen(argv[1]) < MAX_PATH_SIZE) {
        strncpy(file_path, argv[1], MAX_PATH_SIZE - 2);
        file_path[MAX_PATH_SIZE - 1] = '\0';
    } else {
        printf("\033[1;31m[-] Max filepath size is %d bytes.\033[0m\n\n", MAX_PATH_SIZE);
        exit(0);
    }
    
    if(is_directory(file_path)) {
        printf("\033[1;31m[-] Specified a directory, not an ELF file.\033[0m\n\n");
        exit(0);
    }
    
    fd = open(file_path, O_RDONLY);
    if(fd < 0) {
        printf("\033[1;31m[-] File does not exist.\033[0m\n\n");
        exit(0);
    }
    
    fstat(fd, &sb);

    memblock = mmap(NULL, sb.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

    if(memblock == MAP_FAILED) perror("mmap");
    
    if(precheck_bits(memblock) == ELFCLASS32) {
        if(argc > 2)
            launch_checks_x86(memblock, file_path, argv[2]);
        else
            launch_checks_x86(memblock, file_path, NULL);
    } else if(precheck_bits(memblock) == ELFCLASS64) {
        if(argc > 2)
            launch_checks_x86_64(memblock, file_path, argv[2]);
        else
            launch_checks_x86_64(memblock, file_path, NULL);
    } else {
        printf("\033[1;31m[-] Invalid ELF file.\033[0m\n\n");
        exit(0);
    }
        
    printf("\n");
    
    return 0;
    
}


