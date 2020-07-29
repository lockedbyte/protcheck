/*

    Protcheck 1.0.0 - @lockedbyte (https://github.com/lockedbyte/protcheck)
    
        A C utility to check an ELF binary protections parsing the ELF directly instead of using intermediate programs like readelf or grep.
        
*/

#define LIBC_PATH "/usr/bin/lib/libc.so"
#define RELATIVE_PTH "lib/libc.so"

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


// -- functions --
int load_libc(char *libc_path);
int is_pointer_valid(void *p);
int check_canary(void);
int check_RELRO(void);
int check_NX(void);
int check_FORTIFY(void);
int check_PIE(void);
int check_ELF(void);
char *get_arch(void);
char *get_bits(void);
void check_rwx_segments(void);
void check_dangerous_imports(void);
int launch_checks(const char *memchunk, char *file_path, char *libc_path);
// -------------
