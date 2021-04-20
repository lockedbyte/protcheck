/*

    Protcheck 1.0.1 - @lockedbyte (https://github.com/lockedbyte/protcheck)
    
        A C utility to check an ELF binary protections parsing the ELF directly instead of using intermediate programs like readelf or grep.
        
*/

// -- functions --
int load_libc_x86(char *libc_path);
int check_canary_x86(void);
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
