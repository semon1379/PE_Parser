#include "parser.h"

int main(int argc, char* argv[]) {
    
    if (argc != 2) {
        printf("Usage : ./%s <pe_file>\n", argv[0]);
        return 1;
    }
    
    parsing(argv[1]);

	return 0;
}