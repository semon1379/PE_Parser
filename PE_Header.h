#pragma once
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <inttypes.h>
#include <ctypes.h>
#include <capstone/capstone.h>

#define MAX_INSTRUCTION_STRING 256

// Signature
#define IMAGE_DOS_SIGNATURE                 0x5A4D	    // MZ
#define IMAGE_PE_SIGNATURE                  0x00004550	// PE

// Machine type
#define IMAGE_FILE_MACHINE_I386             0x014c      // I386
#define IMAGE_FILE_MACHINE_AMD64            0x8664      // AMD64
#define IMAGE_FILE_MACHINE_IA64             0x0200      // IA64

// PE Characterustics
#define IMAGE_FILE_RELOCS_STRIPPED          0x0001  // 재배치 정보가 제거됨
#define IMAGE_FILE_EXECUTABLE_IMAGE         0x0002  // 실행 가능한 파일
#define IMAGE_FILE_LARGE_ADDRESS_AWARE      0x0020  // 2GB 이상의 주소 공간을 사용할 수 있음
#define IMAGE_FILE_32BIT_MACHINE            0x0100  // 32비트 머신에서 실행 가능
#define IMAGE_FILE_DEBUG_STRIPPED           0x0200  // 디버그 정보가 제거됨
#define IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP  0x0400  // 스왑에서 제거 가능
#define IMAGE_FILE_NET_RUN_FROM_SWAP        0x0800  // 네트워크에서 실행 시 스왑 가능
#define IMAGE_FILE_SYSTEM                   0x1000  // 시스템 파일
#define IMAGE_FILE_DLL                      0x2000  // DLL 파일
#define IMAGE_FILE_UP_SYSTEM_ONLY           0x4000  // 단일 프로세서에서만 실행 가능

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

// section Characteristics
#define IMAGE_SCN_CNT_CODE                   0x00000020
#define IMAGE_SCN_CNT_INITIALIZED_DATA       0x00000040
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA     0x00000080
#define IMAGE_SCN_LNK_INFO                   0x00000200
#define IMAGE_SCN_LNK_REMOVE                 0x00000800
#define IMAGE_SCN_LNK_COMDAT                 0x00001000
#define IMAGE_SCN_NO_DEFER_SPEC_EXC          0x00004000
#define IMAGE_SCN_GPREL                      0x00008000
#define IMAGE_SCN_MEM_FARDATA                0x00008000
#define IMAGE_SCN_MEM_PURGEABLE              0x00020000
#define IMAGE_SCN_MEM_16BIT                  0x00020000
#define IMAGE_SCN_MEM_LOCKED                 0x00040000
#define IMAGE_SCN_MEM_PRELOAD                0x00080000
#define IMAGE_SCN_ALIGN_1BYTES               0x00100000
#define IMAGE_SCN_ALIGN_2BYTES               0x00200000
#define IMAGE_SCN_ALIGN_4BYTES               0x00300000
#define IMAGE_SCN_ALIGN_8BYTES               0x00400000
#define IMAGE_SCN_ALIGN_16BYTES              0x00500000
#define IMAGE_SCN_ALIGN_32BYTES              0x00600000
#define IMAGE_SCN_ALIGN_64BYTES              0x00700000
#define IMAGE_SCN_ALIGN_128BYTES             0x00800000
#define IMAGE_SCN_ALIGN_256BYTES             0x00900000
#define IMAGE_SCN_ALIGN_512BYTES             0x00A00000
#define IMAGE_SCN_ALIGN_1024BYTES            0x00B00000
#define IMAGE_SCN_ALIGN_2048BYTES            0x00C00000
#define IMAGE_SCN_ALIGN_4096BYTES            0x00D00000
#define IMAGE_SCN_ALIGN_8192BYTES            0x00E00000
#define IMAGE_SCN_LNK_NRELOC_OVFL            0x01000000
#define IMAGE_SCN_MEM_DISCARDABLE            0x02000000
#define IMAGE_SCN_MEM_NOT_CACHED             0x04000000
#define IMAGE_SCN_MEM_NOT_PAGED              0x08000000
#define IMAGE_SCN_MEM_SHARED                 0x10000000
#define IMAGE_SCN_MEM_EXECUTE                0x20000000
#define IMAGE_SCN_MEM_READ                   0x40000000
#define IMAGE_SCN_MEM_WRITE                  0x80000000

#define IMAGE_SIZEOF_SHORT_NAME              8
#define MAX_DISPLAY_SIZE                     128
#define MIN(a,b) (((a)<(b))?(a):(b))

typedef struct {
    uint16_t e_magic;
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    int32_t  e_lfanew;
} IMAGE_DOS_HEADER;

typedef struct {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} IMAGE_FILE_HEADER;

typedef struct {
    uint32_t VirtualAddress;
    uint32_t Size;
} IMAGE_DATA_DIRECTORY;

typedef struct {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64;

typedef struct {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32;

typedef struct {
    uint32_t Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64;

typedef struct {
    uint32_t Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32;

typedef struct {
    uint8_t  Name[8];
    union {
        uint32_t PhysicalAddress;
        uint32_t VirtualSize;
    } Misc;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} IMAGE_SECTION_HEADER;

typedef struct {
    uint64_t address;
    uint64_t size;
    char mnemonic[32];
    char op_str[96];
} Instruction;