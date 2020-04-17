#include <stdint.h>

// 64-byte block size
#define BLOCKSIZE 64
// 64 operations each
#define OPNUM 64
// 16-byte digest size
#define DSIZE 16

typedef unsigned char BYTE, *PBYTE;
typedef unsigned char const *PCBYTE;
typedef uint32_t DWORD, *PDWORD;

typedef struct
{
	// states (A, B, C, D)
	DWORD state[4];
	// 128-bit digest/hash
	BYTE digest[DSIZE];
} MD5Context;
