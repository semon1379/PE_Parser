#include "parser.h"

// Directory Entries
const char* directory_entry_names[] = {
    "Export Table",
    "Import Table",
    "Resource Table",
    "Exception Table",
    "Certificate Table",
    "Base Relocation Table",
    "Debug",
    "Architecture (unused)",
    "Global Pointer",
    "TLS Table",
    "Load Config Table",
    "Bound Import Table",
    "Import Address Table (IAT)",
    "Delay Import Descriptor",
    "CLR Runtime Header",
    "Reserved"
};

static int is32bit = 0;

const char* GetFileName(const char* path) {
    const char* filename = strrchr(path, '\\');
    return filename ? filename + 1 : path;
}

int IsPE(const IMAGE_DOS_HEADER* dos_header) {
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        fprintf(stderr, "Not a valid PE file\n");
        return 0;
    }
    return 1;
}

int IsNTSignature(uint32_t nt_signature) {
    if (nt_signature != IMAGE_PE_SIGNATURE) {
        fprintf(stderr, "Not a valid PE header\n");
        return 0;
    }
    return 1;
}

int Is32bitPE(uint16_t file_machine) {
    is32bit = (file_machine == IMAGE_FILE_MACHINE_I386);
    return is32bit;
}

void CreateTime(uint32_t time_stamp) {
    time_t raw_time = (time_t)time_stamp;
    struct tm time_info;
    char time_str[26];

    if (gmtime_s(&time_info, &raw_time) != 0) {
        fprintf(stderr, "gmtime_s error\n");
        return;
    }

    if (asctime_s(time_str, sizeof(time_str), &time_info) != 0) {
        fprintf(stderr, "asctime_s error\n");
        return;
    }

    printf("TimeDateStamp: %s", time_str);
}

void PECharacteristics(uint16_t characteristics) {
    printf("\nPE Characteristics:\n");

    if (characteristics & IMAGE_FILE_RELOCS_STRIPPED) {
        printf("  - Relocation info stripped\n");
    }
    if (characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) {
        printf("  - Executable image\n");
    }
    if (characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE) {
        printf("  - Large address aware\n");
    }
    if (characteristics & IMAGE_FILE_32BIT_MACHINE) {
        printf("  - 32-bit machine\n");
    }
    if (characteristics & IMAGE_FILE_DEBUG_STRIPPED) {
        printf("  - Debug info stripped\n");
    }
    if (characteristics & IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP) {
        printf("  - Removable run from swap\n");
    }
    if (characteristics & IMAGE_FILE_NET_RUN_FROM_SWAP) {
        printf("  - Net run from swap\n");
    }
    if (characteristics & IMAGE_FILE_SYSTEM) {
        printf("  - System file\n");
    }
    if (characteristics & IMAGE_FILE_DLL) {
        printf("  - DLL file\n");
    }
    if (characteristics & IMAGE_FILE_UP_SYSTEM_ONLY) {
        printf("  - Uniprocessor system only\n");
    }
    printf("\n");
}

void DirectoryEntries(IMAGE_DATA_DIRECTORY* data_directory) {
    printf("\nDirectory Entries:\n");
    printf("%-30s %-15s %-15s\n", "Name", "RVA", "Size");
    printf("%-30s %-15s %-15s\n", "-----------------------------", "---------------", "---------------");

    for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {
        uint32_t rva = data_directory[i].VirtualAddress;
        uint32_t size = data_directory[i].Size;
        if (rva != 0 || size != 0) {
            printf("%-30s 0x%-13X %-15u\n", directory_entry_names[i], rva, size);
        }
    }
    printf("\n");
}

void SectionCharacteristics(uint32_t characteristics) {
    printf("    Characteristics:\n");
    if (characteristics & IMAGE_SCN_CNT_CODE)
        printf("      Contains executable code\n");
    if (characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)
        printf("      Contains initialized data\n");
    if (characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
        printf("      Contains uninitialized data\n");
    if (characteristics & IMAGE_SCN_LNK_INFO)
        printf("      Contains comments or other information\n");
    if (characteristics & IMAGE_SCN_LNK_REMOVE)
        printf("      Will not become part of the image\n");
    if (characteristics & IMAGE_SCN_LNK_COMDAT)
        printf("      Contains COMDAT data\n");
    if (characteristics & IMAGE_SCN_MEM_FARDATA)
        printf("      Contains far data\n");
    if (characteristics & IMAGE_SCN_MEM_PURGEABLE)
        printf("      Contains purgeable data\n");
    if (characteristics & IMAGE_SCN_MEM_LOCKED)
        printf("      Is locked\n");
    if (characteristics & IMAGE_SCN_MEM_PRELOAD)
        printf("      Is preloaded\n");
    if (characteristics & IMAGE_SCN_LNK_NRELOC_OVFL)
        printf("      Contains extended relocations\n");
    if (characteristics & IMAGE_SCN_MEM_DISCARDABLE)
        printf("      Can be discarded as needed\n");
    if (characteristics & IMAGE_SCN_MEM_NOT_CACHED)
        printf("      Cannot be cached\n");
    if (characteristics & IMAGE_SCN_MEM_NOT_PAGED)
        printf("      Is not pageable\n");
    if (characteristics & IMAGE_SCN_MEM_SHARED)
        printf("      Can be shared in memory\n");
    if (characteristics & IMAGE_SCN_MEM_EXECUTE)
        printf("      Can be executed as code\n");
    if (characteristics & IMAGE_SCN_MEM_READ)
        printf("      Can be read\n");
    if (characteristics & IMAGE_SCN_MEM_WRITE)
        printf("      Can be written to\n");
}

void ParseSectionHeaders(FILE* file, uint16_t number_of_sections, uint32_t section_table_offset) {
    IMAGE_SECTION_HEADER section_header;

    printf("\nSection Headers:\n");
    printf("Name       VirtSize   VirtAddr   RawSize    RawAddr    Characteristics\n");
    printf("---------- ---------- ---------- ---------- ---------- ----------------\n");

    if (fseek(file, section_table_offset, SEEK_SET) != 0) {
        fprintf(stderr, "Failed to seek to section table\n");
        return;
    }

    for (int i = 0; i < number_of_sections; i++) {
        if (fread(&section_header, sizeof(IMAGE_SECTION_HEADER), 1, file) != 1) {
            fprintf(stderr, "Failed to read section header\n");
            return;
        }

        char name[9] = { 0 }; 
        memcpy(name, section_header.Name, 8);

        printf("%-10s %10u %10u %10u %10u 0x%08X\n",
            name,
            section_header.Misc.VirtualSize,
            section_header.VirtualAddress,
            section_header.SizeOfRawData,
            section_header.PointerToRawData,
            section_header.Characteristics);
        SectionCharacteristics(section_header.Characteristics);
        printf("\n");
    }
}

void PrintHexDump(const uint8_t* data, size_t size) {
    for (size_t i = 0; i < size; i += 16) {
        printf("%08zx: ", i);
        for (size_t j = 0; j < 16; j++) {
            if (i + j < size)
                printf("%02X ", data[i + j]);
            else
                printf("   ");
        }
        printf(" ");
        for (size_t j = 0; j < 16; j++) {
            if (i + j < size)
                printf("%c", isprint(data[i + j]) ? data[i + j] : '.');
            else
                printf(" ");
        }
        printf("\n");
    }
}

void disassemble_text_section(const uint8_t* code, size_t code_size, uint64_t base_address) {
    csh handle;
    cs_insn* insn;
    size_t count;

    if (cs_open(CS_ARCH_X86, is32bit ? CS_MODE_32 : CS_MODE_64, &handle) != CS_ERR_OK) {
        printf("Failed to initialize Capstone\n");
        return;
    }

    count = cs_disasm(handle, code, code_size, base_address, 0, &insn);
    if (count > 0) {
        size_t j;
        printf("Disassembly of .text section:\n");
        for (j = 0; j < count; j++) {
            printf("0x%"PRIx64":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
        }
        cs_free(insn, count);
    }
    else {
        printf("Failed to disassemble code\n");
    }

    cs_close(&handle);
}

void analyze_function_calls(const uint8_t* code, size_t code_size, uint64_t base_address) {
    csh handle;
    cs_insn* insn;
    size_t count;

    if (cs_open(CS_ARCH_X86, is32bit ? CS_MODE_32 : CS_MODE_64, &handle) != CS_ERR_OK) {
        printf("Failed to initialize Capstone\n");
        return;
    }

    count = cs_disasm(handle, code, code_size, base_address, 0, &insn);
    if (count > 0) {
        size_t j;
        printf("\nFunction calls in .text section:\n");
        for (j = 0; j < count; j++) {
            if (strcmp(insn[j].mnemonic, "call") == 0) {
                printf("0x%"PRIx64":\t%s\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
            }
        }
        cs_free(insn, count);
    }

    cs_close(&handle);
}

void find_common_patterns(const uint8_t* code, size_t code_size) {
    printf("\nSearching for common code patterns:\n");

    for (size_t i = 0; i < code_size - 3; i++) {
        
        if ((code[i] == 0x55 && code[i + 1] == 0x89 && code[i + 2] == 0xe5) ||
            (code[i] == 0x55 && code[i + 1] == 0x48 && code[i + 2] == 0x89 && code[i + 3] == 0xe5)) {
            printf("Function prologue found at offset 0x%zx\n", i);
        }
        
        else if ((code[i] == 0x5d && code[i + 1] == 0xc3) ||
            (code[i] == 0x5d && code[i + 1] == 0xc3)) {
            printf("Function epilogue found at offset 0x%zx\n", i);
        }
    }
}

void AnalyzeTextSection(const uint8_t* data, size_t size, uint64_t base_address) {
    printf("Analysis of .text section:\n");
    printf("Size: %zu bytes\n", size);
    printf("Contains executable code\n");

    disassemble_text_section(data, size, base_address);

    analyze_function_calls(data, size, base_address);

    find_common_patterns(data, size);

}

void AnalyzeDataSection(const uint8_t* data, size_t size) {
    printf("Analysis of .data section:\n");
    printf("  Contains initialized data\n");
}

void AnalyzeBssSection(const uint8_t* data, size_t size) {
    printf("Analysis of .bss section:\n");
    printf("  Contains uninitialized data\n");
    printf("  Size: %zu bytes\n", size);
}

void AnalyzeRdataSection(const uint8_t* data, size_t size) {
    printf("Analysis of .rdata section:\n");
    printf("  Contains read-only data\n");
}

void AnalyzeEDataSection(const uint8_t* data, size_t size) {
    printf("Analysis of .edata section:\n");
    printf("  Contains export data\n");
}

void AnalyzeIdataSection(const uint8_t* data, size_t size) {
    printf("Analysis of .idata section:\n");
    printf("  Contains import data\n");
}

void AnalyzeRelocSection(const uint8_t* data, size_t size) {
    printf("Analysis of .reloc section:\n");
    printf("  Contains relocation information\n");
}

void AnalyzeRsrcSection(const uint8_t* data, size_t size) {
    printf("Analysis of .rsrc section:\n");
    printf("  Contains resources\n");
}

void AnalyzePDataSection(const uint8_t* data, size_t size) {
    printf("Analysis of .pdata section:\n");
    printf("  Contains exception handling data\n");
}

void AnalyzeTlsSection(const uint8_t* data, size_t size) {
    printf("Analysis of .tls section:\n");
    printf("  Contains thread-local storage data\n");
}

void AnalyzeSection(const uint8_t* data, size_t size, const char* name, uint64_t base_address) {
    printf("\nAnalysis of section %s:\n", name);

    if (strcmp(name, ".text") == 0) {
        AnalyzeTextSection(data, size, base_address);
    }
    else if (strcmp(name, ".data") == 0) {
        AnalyzeDataSection(data, size);
    }
    else if (strcmp(name, ".bss") == 0) {
        AnalyzeBssSection(data, size);
    }
    else if (strcmp(name, ".rdata") == 0) {
        AnalyzeRdataSection(data, size);
    }
    else if (strcmp(name, ".edata") == 0) {
        AnalyzeEDataSection(data, size);
    }
    else if (strcmp(name, ".idata") == 0) {
        AnalyzeIdataSection(data, size);
    }
    else if (strcmp(name, ".reloc") == 0) {
        AnalyzeRelocSection(data, size);
    }
    else if (strcmp(name, ".rsrc") == 0) {
        AnalyzeRsrcSection(data, size);
    }
    else if (strcmp(name, ".pdata") == 0) {
        AnalyzePDataSection(data, size);
    }
    else if (strcmp(name, ".tls") == 0) {
        AnalyzeTlsSection(data, size);
    }
    else {
        printf("  Unknown section type\n");
    }

    printf("Searching for ASCII strings...\n");
    for (size_t i = 0; i < size - 4; i++) {
        if (isprint(data[i])) {
            size_t len = 0;
            while (i + len < size && isprint(data[i + len])) len++;
            if (len > 4) {
                printf("Found string at offset %zu: ", i);
                for (size_t j = 0; j < len; j++) {
                    putchar(data[i + j]);
                }
                printf("\n");
                i += len - 1;
            }
        }
    }
    printf("\n");
}

void ParseSectionData(FILE* file, IMAGE_SECTION_HEADER* section_header, uint64_t image_base) {
    uint8_t* section_data = (uint8_t*)malloc(section_header->SizeOfRawData);
    if (!section_data) {
        fprintf(stderr, "Memory allocation failed for section data\n");
        return;
    }

    if (fseek(file, section_header->PointerToRawData, SEEK_SET) != 0) {
        fprintf(stderr, "Failed to seek to section data\n");
        free(section_data);
        return;
    }

    size_t bytes_read = fread(section_data, 1, section_header->SizeOfRawData, file);
    if (bytes_read != section_header->SizeOfRawData) {
        fprintf(stderr, "Failed to read section data (read %zu of %u bytes)\n",
            bytes_read, section_header->SizeOfRawData);
        free(section_data);
        return;
    }

    char section_name[IMAGE_SIZEOF_SHORT_NAME + 1] = { 0 };
    memcpy(section_name, section_header->Name, IMAGE_SIZEOF_SHORT_NAME);

    printf("\nSection Name: %s\n", section_name);
    printf("Section Size: %u bytes\n", section_header->SizeOfRawData);

    size_t display_size = MIN(MAX_DISPLAY_SIZE, section_header->SizeOfRawData);
    printf("First %zu bytes of section data:\n", display_size);
    PrintHexDump(section_data, display_size);

    uint64_t base_address = image_base + section_header->VirtualAddress;
    AnalyzeSection(section_data, section_header->SizeOfRawData, section_name, base_address);

    free(section_data);
}



void ParseAllSections(FILE* file, uint16_t number_of_sections, uint32_t section_table_offset, uint64_t image_base) {
    IMAGE_SECTION_HEADER section_header;

    for (int i = 0; i < number_of_sections; i++) {
        if (fseek(file, section_table_offset + i * sizeof(IMAGE_SECTION_HEADER), SEEK_SET) != 0) {
            fprintf(stderr, "Failed to seek to section header\n");
            return;
        }

        if (fread(&section_header, sizeof(IMAGE_SECTION_HEADER), 1, file) != 1) {
            fprintf(stderr, "Failed to read section header\n");
            return;
        }

        ParseSectionData(file, &section_header, image_base);
    }
}

void parsing(const char* path) {
    FILE* file = NULL;
    const char* filename = GetFileName(path);

    if (fopen_s(&file, path, "rb") != 0) {
        fprintf(stderr, "File open error");
        return;
    }

    IMAGE_DOS_HEADER dos_header;
    if (fread(&dos_header, sizeof(IMAGE_DOS_HEADER), 1, file) != 1) {
        fprintf(stderr, "Failed to read DOS header\n");
        fclose(file);
        return;
    }

    if (!IsPE(&dos_header)) {
        fclose(file);
        return;
    }

    printf("PE File Name: %s\n", filename);

    if (fseek(file, dos_header.e_lfanew, SEEK_SET) != 0) {
        fprintf(stderr, "Failed to seek to PE header\n");
        fclose(file);
        return;
    }

    uint32_t nt_signature;
    if (fread(&nt_signature, sizeof(uint32_t), 1, file) != 1) {
        fprintf(stderr, "Failed to read NT signature\n");
        fclose(file);
        return;
    }

    if (!IsNTSignature(nt_signature)) {
        fclose(file);
        return;
    }

    uint16_t file_machine;
    if (fread(&file_machine, sizeof(uint16_t), 1, file) != 1) {
        fprintf(stderr, "Failed to read file machine\n");
        fclose(file);
        return;
    }

    if (fseek(file, dos_header.e_lfanew, SEEK_SET) != 0) {
        fprintf(stderr, "Failed to seek back to PE header\n");
        fclose(file);
        return;
    }

    if (Is32bitPE(file_machine)) {
        NT_Parsing32(file);
    }
    else {
        NT_Parsing64(file, file_machine);
    }

    fclose(file);
}


void ParseFileOptional32(IMAGE_NT_HEADERS32 nt_headers) {
    CreateTime(nt_headers.FileHeader.TimeDateStamp);
    PECharacteristics(nt_headers.FileHeader.Characteristics);
    printf("Linker Version : %d.%d\n", nt_headers.OptionalHeader.MajorLinkerVersion, nt_headers.OptionalHeader.MinorLinkerVersion);

    printf("Entry Point : 0x%" PRIx32 "\n", nt_headers.OptionalHeader.ImageBase + nt_headers.OptionalHeader.AddressOfEntryPoint);

    printf("Code Section VA : 0x%" PRIx32 "\n", nt_headers.OptionalHeader.ImageBase + nt_headers.OptionalHeader.BaseOfCode);

    printf("Size of Image : 0x%" PRIx32 "\n", nt_headers.OptionalHeader.SizeOfImage);

    printf("Size of Header : 0x%" PRIx32 "\n", nt_headers.OptionalHeader.SizeOfHeaders);

    if (nt_headers.OptionalHeader.CheckSum == 0) {
        printf("CheckSum : Not Set\n");
    }
    else {
        printf("CheckSum : %d \n", nt_headers.OptionalHeader.CheckSum);
    }

    DirectoryEntries(nt_headers.OptionalHeader.DataDirectory);
}

void ParseFileOptional64(IMAGE_NT_HEADERS64 nt_headers) {
    CreateTime(nt_headers.FileHeader.TimeDateStamp);
    PECharacteristics(nt_headers.FileHeader.Characteristics);
    printf("Linker Version : %d.%d\n", nt_headers.OptionalHeader.MajorLinkerVersion, nt_headers.OptionalHeader.MinorLinkerVersion);

    printf("Entry Point : 0x%" PRIx64 "\n", nt_headers.OptionalHeader.ImageBase + nt_headers.OptionalHeader.AddressOfEntryPoint);

    printf("Code Section VA : 0x%" PRIx64 "\n", nt_headers.OptionalHeader.ImageBase + nt_headers.OptionalHeader.BaseOfCode);

    printf("Size of Image : 0x%" PRIx32 "\n", nt_headers.OptionalHeader.SizeOfImage);

    printf("Size of Header : 0x%" PRIx32 "\n", nt_headers.OptionalHeader.SizeOfHeaders);

    if (nt_headers.OptionalHeader.CheckSum == 0) {
        printf("CheckSum : Not Set\n");
    } else {
        printf("CheckSum : %d \n", nt_headers.OptionalHeader.CheckSum);
    }

    DirectoryEntries(nt_headers.OptionalHeader.DataDirectory);
}

void NT_Parsing32(FILE * file) {
    IMAGE_NT_HEADERS32 nt_headers;

    fread_s(&nt_headers, sizeof(IMAGE_NT_HEADERS32), sizeof(IMAGE_NT_HEADERS32), 1, file);

    printf("Machine : Intel 386 (x86)\n");
    printf("Size of image: %d bytes\n", nt_headers.OptionalHeader.SizeOfImage);

    ParseFileOptional32(nt_headers);

    printf("Number of sections: %d\n", nt_headers.FileHeader.NumberOfSections);
    uint32_t section_table_offset = ftell(file);
    ParseSectionHeaders(file, nt_headers.FileHeader.NumberOfSections, section_table_offset);
    ParseAllSections(file, nt_headers.FileHeader.NumberOfSections, section_table_offset, nt_headers.OptionalHeader.ImageBase);
}


void NT_Parsing64(FILE* file, uint16_t file_machine) {
    
    if (file_machine == IMAGE_FILE_MACHINE_AMD64) {
        
        printf("Machine : AMD64 (x86_64)\n");

    }
    else {
        
        printf("Machine : Intel Itanium (x86_64)\n");

    }
    
    IMAGE_NT_HEADERS64 nt_headers;
    
    fread_s(&nt_headers, sizeof(IMAGE_NT_HEADERS64), sizeof(IMAGE_NT_HEADERS64), 1, file);
    printf("Size of image: %d bytes\n", nt_headers.OptionalHeader.SizeOfImage);

    ParseFileOptional64(nt_headers);


    printf("Number of sections: %d\n", nt_headers.FileHeader.NumberOfSections);
    uint32_t section_table_offset = ftell(file);
    ParseSectionHeaders(file, nt_headers.FileHeader.NumberOfSections, section_table_offset);
    ParseAllSections(file, nt_headers.FileHeader.NumberOfSections, section_table_offset, nt_headers.OptionalHeader.ImageBase);
}
