/*

    Protcheck 1.0.0 - @lockedbyte (https://github.com/lockedbyte/protcheck)
    
        A C utility to check an ELF binary protections parsing the ELF directly instead of using intermediate programs like readelf or grep.
        
*/

/* ------------------------------------------------- */
/* This values are extracted from /usr/include/elf.h */
/* ------------------------------------------------- */

/* This file defines standard ELF types, structures, and macros.
   Copyright (C) 1995-2019 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

/* --------------------------------------------------- */

#include <sys/types.h>

#define ELFMAG "\177ELF"                   /* elf magic */
#define BIT_INDENT_INDEX 0x4               /* bit spec idx */
#define ELF_32_T_STR "ELF x86 (32-bit)"    /* Str for 32-bit ELF */
#define ELF_64_T_STR "ELF x86_64 (64-bit)" /* Str for 64-bit ELF */

typedef uint16_t Elf32_Half;
typedef uint16_t Elf64_Half;

typedef uint32_t Elf32_Word;
typedef	int32_t  Elf32_Sword;
typedef uint32_t Elf64_Word;
typedef	int32_t  Elf64_Sword;

typedef uint64_t Elf32_Xword;
typedef	int64_t  Elf32_Sxword;
typedef uint64_t Elf64_Xword;
typedef	int64_t  Elf64_Sxword;

typedef uint32_t Elf32_Addr;
typedef uint64_t Elf64_Addr;

typedef uint32_t Elf32_Off;
typedef uint64_t Elf64_Off;

typedef uint16_t Elf32_Section;
typedef uint16_t Elf64_Section;

typedef Elf32_Half Elf32_Versym;
typedef Elf64_Half Elf64_Versym;

#define EI_NIDENT (16)              /* magic size */

typedef struct {
  unsigned char	e_ident[EI_NIDENT];	/* Magic number and other info */
  Elf32_Half	e_type;			    /* Object file type */
  Elf32_Half	e_machine;		    /* Architecture */
  Elf32_Word	e_version;		    /* Object file version */
  Elf32_Addr	e_entry;		    /* Entry point virtual address */
  Elf32_Off	    e_phoff;		    /* Program header table file offset */
  Elf32_Off	    e_shoff;		    /* Section header table file offset */
  Elf32_Word	e_flags;		    /* Processor-specific flags */
  Elf32_Half	e_ehsize;		    /* ELF header size in bytes */
  Elf32_Half	e_phentsize;	    /* Program header table entry size */
  Elf32_Half	e_phnum;		    /* Program header table entry count */
  Elf32_Half	e_shentsize;	    /* Section header table entry size */
  Elf32_Half	e_shnum;		    /* Section header table entry count */
  Elf32_Half	e_shstrndx;		    /* Section header string table index */
} Elf32_Ehdr;

typedef struct {
  unsigned char	e_ident[EI_NIDENT];	/* Magic number and other info */
  Elf64_Half	e_type;			    /* Object file type */
  Elf64_Half	e_machine;		    /* Architecture */
  Elf64_Word	e_version;		    /* Object file version */
  Elf64_Addr	e_entry;		    /* Entry point virtual address */
  Elf64_Off	    e_phoff;		    /* Program header table file offset */
  Elf64_Off	    e_shoff;		    /* Section header table file offset */
  Elf64_Word	e_flags;		    /* Processor-specific flags */
  Elf64_Half	e_ehsize;		    /* ELF header size in bytes */
  Elf64_Half	e_phentsize;		/* Program header table entry size */
  Elf64_Half	e_phnum;		    /* Program header table entry count */
  Elf64_Half	e_shentsize;		/* Section header table entry size */
  Elf64_Half	e_shnum;		    /* Section header table entry count */
  Elf64_Half	e_shstrndx;		    /* Section header string table index */
} Elf64_Ehdr;

#define ELFCLASS32	0x1		/* 32-bit objects */
#define ELFCLASS64	0x2		/* 64-bit objects */

/* e_type */
#define ET_NONE		0x0		    /* No file type */
#define ET_REL		0x1		    /* Relocatable file */
#define ET_EXEC		0x2		    /* Executable file */
#define ET_DYN		0x3		    /* Shared object file */
#define ET_CORE		0x4		    /* Core file */
#define	ET_NUM		5		    /* Number of defined types */
#define ET_LOOS		0xfe00		/* OS-specific range start */
#define ET_HIOS		0xfeff		/* OS-specific range end */
#define ET_LOPROC	0xff00		/* Processor-specific range start */
#define ET_HIPROC	0xffff		/* Processor-specific range end */

/* e_machine */
#define EM_386		0x3	    /* Intel 80386 */
#define EM_860		0x7	    /* Intel 80860 */
#define EM_ARM		0x28	/* ARM */
#define EM_X86_64	0x3e	/* AMD x86-64 architecture */

/* e_version */
#define EV_NONE		0x0		/* Invalid ELF version */
#define EV_CURRENT	0x1		/* Current version */
#define EV_NUM		0x2     /* Num */

typedef struct {
  Elf32_Word	sh_name;		/* Section name (string tbl index) */
  Elf32_Word	sh_type;		/* Section type */
  Elf32_Word	sh_flags;		/* Section flags */
  Elf32_Addr	sh_addr;		/* Section virtual addr at execution */
  Elf32_Off	    sh_offset;		/* Section file offset */
  Elf32_Word	sh_size;		/* Section size in bytes */
  Elf32_Word	sh_link;		/* Link to another section */
  Elf32_Word	sh_info;		/* Additional section information */
  Elf32_Word	sh_addralign;	/* Section alignment */
  Elf32_Word	sh_entsize;		/* Entry size if section holds table */
} Elf32_Shdr;

typedef struct {
  Elf64_Word	sh_name;		/* Section name (string tbl index) */
  Elf64_Word	sh_type;		/* Section type */
  Elf64_Xword	sh_flags;		/* Section flags */
  Elf64_Addr	sh_addr;		/* Section virtual addr at execution */
  Elf64_Off	    sh_offset;		/* Section file offset */
  Elf64_Xword	sh_size;		/* Section size in bytes */
  Elf64_Word	sh_link;		/* Link to another section */
  Elf64_Word	sh_info;		/* Additional section information */
  Elf64_Xword	sh_addralign;	/* Section alignment */
  Elf64_Xword	sh_entsize;		/* Entry size if section holds table */
} Elf64_Shdr;

/* sh_type */

#define SHT_NULL	        0x0		    /* Section header table entry unused */
#define SHT_PROGBITS	    0x1		    /* Program data */
#define SHT_SYMTAB	        0x2		    /* Symbol table */
#define SHT_STRTAB	        0x3		    /* String table */
#define SHT_RELA	        0x4		    /* Relocation entries with addends */
#define SHT_HASH	        0x5		    /* Symbol hash table */
#define SHT_DYNAMIC	        0x6		    /* Dynamic linking information */
#define SHT_NOTE	        0x7		    /* Notes */
#define SHT_NOBITS	        0x8		    /* Program space with no data (bss) */
#define SHT_REL		        0x9		    /* Relocation entries, no addends */
#define SHT_SHLIB	        0xa		    /* Reserved */
#define SHT_DYNSYM	        0xb		    /* Dynamic linker symbol table */
#define SHT_INIT_ARRAY	    0xe		    /* Array of constructors */
#define SHT_FINI_ARRAY	    0xf		    /* Array of destructors */
#define SHT_PREINIT_ARRAY   0x10		/* Array of pre-constructors */
#define SHT_GROUP	        0x11		/* Section group */
#define SHT_SYMTAB_SHNDX    0x12		/* Extended section indeces */
#define	SHT_NUM		        0x13		/* Number of defined types.  */
#define SHT_LOOS	        0x60000000	/* Start OS-specific.  */
#define SHT_GNU_ATTRIBUTES  0x6ffffff5	/* Object attributes.  */
#define SHT_GNU_HASH	    0x6ffffff6	/* GNU-style hash table.  */
#define SHT_GNU_LIBLIST	    0x6ffffff7	/* Prelink library list */
#define SHT_CHECKSUM	    0x6ffffff8	/* Checksum for DSO content.  */
#define SHT_LOSUNW	        0x6ffffffa	/* Sun-specific low bound.  */
#define SHT_SUNW_move	    0x6ffffffa
#define SHT_SUNW_COMDAT     0x6ffffffb
#define SHT_SUNW_syminfo    0x6ffffffc
#define SHT_GNU_verdef	    0x6ffffffd	/* Version definition section.  */
#define SHT_GNU_verneed	    0x6ffffffe	/* Version needs section.  */
#define SHT_GNU_versym	    0x6fffffff	/* Version symbol table.  */
#define SHT_HISUNW	        0x6fffffff	/* Sun-specific high bound.  */
#define SHT_HIOS	        0x6fffffff	/* End OS-specific type */
#define SHT_LOPROC	        0x70000000	/* Start of processor-specific */
#define SHT_HIPROC	        0x7fffffff	/* End of processor-specific */
#define SHT_LOUSER	        0x80000000	/* Start of application-specific */
#define SHT_HIUSER	        0x8fffffff	/* End of application-specific */

typedef struct {
  Elf32_Addr	r_offset;		/* Address */
  Elf32_Word	r_info;			/* Relocation type and symbol index */
  Elf32_Sword	r_addend;		/* Addend */
} Elf32_Rela;

typedef struct {
  Elf64_Addr	r_offset;		/* Address */
  Elf64_Xword	r_info;			/* Relocation type and symbol index */
  Elf64_Sxword	r_addend;		/* Addend */
} Elf64_Rela;


#define ELF32_ST_BIND(val)		(((unsigned char) (val)) >> 4)
#define ELF32_ST_TYPE(val)		((val) & 0xf)
#define ELF32_ST_INFO(bind, type)	(((bind) << 4) + ((type) & 0xf))

#define ELF64_ST_BIND(val)		ELF32_ST_BIND (val)
#define ELF64_ST_TYPE(val)		ELF32_ST_TYPE (val)
#define ELF64_ST_INFO(bind, type)	ELF32_ST_INFO ((bind), (type))

#define ELF32_R_SYM(val)		((val) >> 8)
#define ELF32_R_TYPE(val)		((val) & 0xff)
#define ELF32_R_INFO(sym, type)		(((sym) << 8) + ((type) & 0xff))

#define ELF64_R_SYM(i)			((i) >> 32)
#define ELF64_R_TYPE(i)			((i) & 0xffffffff)
#define ELF64_R_INFO(sym,type)		((((Elf64_Xword) (sym)) << 32) + (type))

typedef struct {
  Elf32_Word	st_name;		/* Symbol name (string tbl index) */
  Elf32_Addr	st_value;		/* Symbol value */
  Elf32_Word	st_size;		/* Symbol size */
  unsigned char	st_info;		/* Symbol type and binding */
  unsigned char	st_other;		/* Symbol visibility */
  Elf32_Section	st_shndx;		/* Section index */
} Elf32_Sym;

typedef struct {
  Elf64_Word	st_name;		/* Symbol name (string tbl index) */
  unsigned char	st_info;		/* Symbol type and binding */
  unsigned char st_other;		/* Symbol visibility */
  Elf64_Section	st_shndx;		/* Section index */
  Elf64_Addr	st_value;		/* Symbol value */
  Elf64_Xword	st_size;		/* Symbol size */
} Elf64_Sym;

#define STB_LOCAL	0x0		/* Local symbol */
#define STB_GLOBAL	0x1		/* Global symbol */
#define STB_WEAK	0x2		/* Weak symbol */
#define	STB_NUM		0x3		/* Number of defined types.  */
#define STB_LOOS	0xa		/* Start of OS-specific */
#define STB_HIOS	0xc		/* End of OS-specific */
#define STB_LOPROC	0xd		/* Start of processor-specific */
#define STB_HIPROC	0xf		/* End of processor-specific */

#define STT_NOTYPE	0x0		/* Symbol type is unspecified */
#define STT_OBJECT	0x1		/* Symbol is a data object */
#define STT_FUNC	0x2		/* Symbol is a code object */
#define STT_SECTION	0x3		/* Symbol associated with a section */
#define STT_FILE	0x4		/* Symbol's name is file name */
#define STT_COMMON	0x5		/* Symbol is a common data object */
#define STT_TLS		0x6		/* Symbol is thread-local data object*/
#define	STT_NUM		0x7		/* Number of defined types.  */
#define STT_LOOS	0xa		/* Start of OS-specific */
#define STT_HIOS	0xc		/* End of OS-specific */
#define STT_LOPROC	0xd		/* Start of processor-specific */
#define STT_HIPROC	0xf		/* End of processor-specific */

typedef struct {
  Elf32_Sword	d_tag;			/* Dynamic entry type */
  union {
      Elf32_Word d_val;			/* Integer value */
      Elf32_Addr d_ptr;			/* Address value */
    } d_un;
} Elf32_Dyn;

typedef struct {
  Elf64_Sxword	d_tag;			/* Dynamic entry type */
  union {
      Elf64_Xword d_val;		/* Integer value */
      Elf64_Addr d_ptr;			/* Address value */
    } d_un;
} Elf64_Dyn;

typedef struct {
  Elf32_Word	p_type;			/* Segment type */
  Elf32_Off	    p_offset;		/* Segment file offset */
  Elf32_Addr	p_vaddr;		/* Segment virtual address */
  Elf32_Addr	p_paddr;		/* Segment physical address */
  Elf32_Word	p_filesz;		/* Segment size in file */
  Elf32_Word	p_memsz;		/* Segment size in memory */
  Elf32_Word	p_flags;		/* Segment flags */
  Elf32_Word	p_align;		/* Segment alignment */
} Elf32_Phdr;

typedef struct {
  Elf64_Word	p_type;			/* Segment type */
  Elf64_Word	p_flags;		/* Segment flags */
  Elf64_Off	    p_offset;		/* Segment file offset */
  Elf64_Addr	p_vaddr;		/* Segment virtual address */
  Elf64_Addr	p_paddr;		/* Segment physical address */
  Elf64_Xword	p_filesz;		/* Segment size in file */
  Elf64_Xword	p_memsz;		/* Segment size in memory */
  Elf64_Xword	p_align;		/* Segment alignment */
} Elf64_Phdr;

#define	PT_NULL		    0x0		    /* Program header table entry unused */
#define PT_LOAD		    0x1		    /* Loadable program segment */
#define PT_DYNAMIC	    0x2		    /* Dynamic linking information */
#define PT_INTERP	    0x3		    /* Program interpreter */
#define PT_NOTE		    0x4		    /* Auxiliary information */
#define PT_SHLIB	    0x5		    /* Reserved */
#define PT_PHDR		    0x6		    /* Entry for header table itself */
#define PT_TLS		    0x7		    /* Thread-local storage segment */
#define	PT_NUM		    0x8		    /* Number of defined types */
#define PT_LOOS		    0x60000000	/* Start of OS-specific */
#define PT_GNU_EH_FRAME	0x6474e550	/* GCC .eh_frame_hdr segment */
#define PT_GNU_STACK	0x6474e551	/* Indicates stack executability */
#define PT_GNU_RELRO	0x6474e552	/* Read-only after relocation */
#define PT_LOSUNW	    0x6ffffffa  /* PT_LOSUNW */
#define PT_SUNWBSS	    0x6ffffffa	/* Sun Specific segment */
#define PT_SUNWSTACK	0x6ffffffb	/* Stack segment */
#define PT_HISUNW	    0x6fffffff  /* PT_HISUNW */
#define PT_HIOS		    0x6fffffff	/* End of OS-specific */
#define PT_LOPROC	    0x70000000	/* Start of processor-specific */
#define PT_HIPROC	    0x7fffffff	/* End of processor-specific */

#define DT_NULL		0		/* Marks end of dynamic section */
#define DT_NEEDED	1		/* Name of needed library */
#define DT_PLTRELSZ	2		/* Size in bytes of PLT relocs */
#define DT_PLTGOT	3		/* Processor defined value */
#define DT_HASH		4		/* Address of symbol hash table */
#define DT_STRTAB	5		/* Address of string table */
#define DT_SYMTAB	6		/* Address of symbol table */
#define DT_RELA		7		/* Address of Rela relocs */
#define DT_RELASZ	8		/* Total size of Rela relocs */
#define DT_RELAENT	9		/* Size of one Rela reloc */
#define DT_STRSZ	10		/* Size of string table */
#define DT_SYMENT	11		/* Size of one symbol table entry */
#define DT_INIT		12		/* Address of init function */
#define DT_FINI		13		/* Address of termination function */
#define DT_SONAME	14		/* Name of shared object */
#define DT_RPATH	15		/* Library search path (deprecated) */
#define DT_SYMBOLIC	16		/* Start symbol search here */
#define DT_REL		17		/* Address of Rel relocs */
#define DT_RELSZ	18		/* Total size of Rel relocs */
#define DT_RELENT	19		/* Size of one Rel reloc */
#define DT_PLTREL	20		/* Type of reloc in PLT */
#define DT_DEBUG	21		/* For debugging; unspecified */
#define DT_TEXTREL	22		/* Reloc might modify .text */
#define DT_JMPREL	23		/* Address of PLT relocs */
#define	DT_BIND_NOW	24		/* Process relocations of object */
#define	DT_INIT_ARRAY	25		/* Array with addresses of init fct */
#define	DT_FINI_ARRAY	26		/* Array with addresses of fini fct */
#define	DT_INIT_ARRAYSZ	27		/* Size in bytes of DT_INIT_ARRAY */
#define	DT_FINI_ARRAYSZ	28		/* Size in bytes of DT_FINI_ARRAY */
#define DT_RUNPATH	29		/* Library search path */
#define DT_FLAGS	30		/* Flags for the object being loaded */
#define DT_ENCODING	32		/* Start of encoded range */
#define DT_PREINIT_ARRAY 32		/* Array with addresses of preinit fct*/
#define DT_PREINIT_ARRAYSZ 33		/* size in bytes of DT_PREINIT_ARRAY */
#define DT_SYMTAB_SHNDX	34		/* Address of SYMTAB_SHNDX section */
#define	DT_NUM		35		/* Number used */
#define DT_LOOS		0x6000000d	/* Start of OS-specific */
#define DT_HIOS		0x6ffff000	/* End of OS-specific */
#define DT_LOPROC	0x70000000	/* Start of processor-specific */
#define DT_HIPROC	0x7fffffff	/* End of processor-specific */
#define	DT_PROCNUM	DT_MIPS_NUM	/* Most used by any processor */
#define DT_GNU_CONFLICTSZ 0x6ffffdf6	/* Size of conflict section */
#define DT_GNU_LIBLISTSZ 0x6ffffdf7	/* Size of library list */
#define DT_CHECKSUM	0x6ffffdf8
#define DT_PLTPADSZ	0x6ffffdf9
#define DT_MOVEENT	0x6ffffdfa
#define DT_MOVESZ	0x6ffffdfb
#define DT_FEATURE_1	0x6ffffdfc	/* Feature selection (DTF_*).  */
#define DT_POSFLAG_1	0x6ffffdfd	/* Flags for DT_* entries, effecting
					   the following DT_* entry.  */
#define DT_SYMINSZ	0x6ffffdfe	/* Size of syminfo table (in bytes) */
#define DT_SYMINENT	0x6ffffdff	/* Entry size of syminfo */
#define DT_VALRNGHI	0x6ffffdff
#define DT_VALTAGIDX(tag)	(DT_VALRNGHI - (tag))	/* Reverse order! */
#define DT_VALNUM 12
#define DT_TLSDESC_PLT	0x6ffffef6
#define DT_TLSDESC_GOT	0x6ffffef7
#define DT_GNU_CONFLICT	0x6ffffef8	/* Start of conflict section */
#define DT_GNU_LIBLIST	0x6ffffef9	/* Library list */
#define DT_CONFIG	0x6ffffefa	/* Configuration information.  */
#define DT_DEPAUDIT	0x6ffffefb	/* Dependency auditing.  */
#define DT_AUDIT	0x6ffffefc	/* Object auditing.  */
#define	DT_PLTPAD	0x6ffffefd	/* PLT padding.  */
#define	DT_MOVETAB	0x6ffffefe	/* Move table.  */
#define DT_SYMINFO	0x6ffffeff	/* Syminfo table.  */
#define DT_ADDRRNGHI	0x6ffffeff
#define DT_ADDRTAGIDX(tag)	(DT_ADDRRNGHI - (tag))	/* Reverse order! */
#define DT_ADDRNUM 11
#define DT_VERSYM	0x6ffffff0
#define DT_RELACOUNT	0x6ffffff9
#define DT_RELCOUNT	0x6ffffffa
#define DT_FLAGS_1	0x6ffffffb	/* State flags, see DF_1_* below.  */


