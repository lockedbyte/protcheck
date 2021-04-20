/*

    Protcheck 1.0.0 - @lockedbyte (https://github.com/lockedbyte/protcheck)
    
        A C utility to check an ELF binary protections parsing the ELF directly instead of using intermediate programs like readelf or grep.
        
*/


#define LIBC_PATH_x86 "/usr/bin/lib/libc_x86.so"
#define LIBC_PATH_x86_64 "/usr/bin/lib/libc_x86_64.so"

#define RELATIVE_PTH_x86 "./lib/libc_x86.so"
#define RELATIVE_PTH_x86_64 "./lib/libc_x86_64.so"

#define CHECK_BIT(var,pos) ((var) & (1<<(pos)))

#define BIND_NOW_BIT_POS 0x3

#define RWE_PROT 0x7
#define RW_PROT 0x6

#define CANARY_CLUE_1 "__stack_chk_fail"
#define CANARY_CLUE_2 "__intel_security_cookie"

#define CANARY_TRUE 1
#define CANARY_FALSE 0

#define FORTIFY_TRUE 1
#define FORTIFY_FALSE 0

#define NX_TRUE 1
#define NX_FALSE 0

#define RELRO_FULL 2
#define RELRO_PARTIAL 1
#define RELRO_FALSE 0

#define PIE_TRUE 1
#define PIE_FALSE 0

#define EM_386_STR "Intel 80386"
#define EM_860_STR "Intel 80860"
#define EM_X86_64_STR "AMD x86-64"
#define EM_ARM_STR "ARM"
#define UNKNOWN_STR "Unknown"

#define ELF_UNK_T_STR "Unknown"

