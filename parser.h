#pragma once
#include "PE_Header.h"

const char* GetFileName(const char* path);
int IsPE(const IMAGE_DOS_HEADER* dos_header);
int IsNTSignature(uint32_t nt_signature);
int Is32bitPE(uint16_t file_machine);
void CreateTime(uint32_t time_stamp);
void PECharacteristics(uint16_t characteristics);
void ParseFileOptional32(IMAGE_NT_HEADERS32 nt_headers);
void ParseFileOptional64(IMAGE_NT_HEADERS64 nt_headers);

void parsing(const char* filename);
void NT_Parsing32(FILE* file);
void NT_Parsing64(FILE* file, uint16_t file_machine);
