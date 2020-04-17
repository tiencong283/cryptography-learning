/*
a insecure implementation of MD5 hash algorithm which follows guidelines in rfc1321
only deals with bytes instead of bits as in specification

https://tools.ietf.org/html/rfc1321
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "md5.h"

// four auxiliary functions
#define F(x, y, z) ((x) & (y)) | ((~x) & (z))
#define G(x, y, z) ((x) & (z)) | ((y) & (~z))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32 - n)))

// alternative: floor(2**32 * abs(sin(i + 1)) for i in range(OPNUM)
DWORD K[OPNUM] = {
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
	0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
	0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
	0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
	0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
	0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
	0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
	0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};

// the per-round shift table
DWORD S[OPNUM] = {
	7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
	5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
	4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
	6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

// initialize MD5 states
void MD5Init(MD5Context *context)
{
	assert(context != NULL);

	context->state[0] = 0x67452301;
	context->state[1] = 0xefcdab89;
	context->state[2] = 0x98badcfe;
	context->state[3] = 0x10325476;
}

// handle padding (step 3.1, 3.2 in rfc)
static unsigned char *extendMsg(PCBYTE msg, size_t size, size_t *pNewSize)
{
	size_t newSize;
	unsigned char *newMsg;
	int r = size % BLOCKSIZE;
	int q = size / BLOCKSIZE;

	if (r < 56)
	{
		newSize = (q + 1) * BLOCKSIZE;
	}
	else
	{
		newSize = (q + 2) * BLOCKSIZE;
	}
	assert(newSize % BLOCKSIZE == 0);

	newMsg = (unsigned char *)malloc(newSize);
	if (newMsg == NULL)
	{
		perror("malloc");
		return NULL;
	}
	memcpy(newMsg, msg, size);
	// append bit 1 to the end of msg followed by 0's
	memset(&newMsg[size], 0, newSize - size);
	newMsg[size] = '\x80';
	// the last 64 bits -> the original len of the message in bits
	*(long long *)&newMsg[newSize - 8] = size * 8;

	*pNewSize = newSize;
	return newMsg;
}

// process each chunks
void MD5Transform(MD5Context *context, PBYTE msg, size_t size)
{
	int numOfBlocks = size / BLOCKSIZE;
	PDWORD pState = context->state;
	PDWORD pBlock = NULL;

	for (int bi = 0; bi < numOfBlocks; ++bi)
	{ // each block
		DWORD a = pState[0];
		DWORD b = pState[1];
		DWORD c = pState[2];
		DWORD d = pState[3];

		pBlock = (PDWORD)&msg[BLOCKSIZE * bi];
		DWORD temp = 0;
		int g = 0;

		for (int r = 0; r < 64; r++)
		{ // 64 rounds
			if (r <= 15)
			{ // round 1
				temp = F(b, c, d);
				g = r;
			}
			else if (r <= 31)
			{ // round 2
				temp = G(b, c, d);
				g = (5 * r + 1) % 16;
			}
			else if (r <= 47)
			{ // round 3
				temp = H(b, c, d);
				g = (3 * r + 5) % 16;
			}
			else
			{ // round 4
				temp = I(b, c, d);
				g = (7 * r) % 16;
			}
			temp += pBlock[g] + K[r] + a;
			// swaps
			a = d;
			d = c;
			c = b;
			b = b + ROTATE_LEFT(temp, S[r]);
		}
		// update state
		pState[0] += a;
		pState[1] += b;
		pState[2] += c;
		pState[3] += d;
	}
}

// update MD5 state, standard MD5Update will support in-fly hasing
void MD5Update(MD5Context *context, PCBYTE msg, size_t size)
{
	PBYTE eMsg = NULL;
	size_t eSize = 0;

	if ((eMsg = extendMsg(msg, size, &eSize)) == NULL)
	{
		return;
	}
	MD5Transform(context, eMsg, eSize);

	free(eMsg);
}
// calculate digest from the state
void MD5Final(MD5Context *context)
{
	PBYTE digest = context->digest;
	memset(digest, 0, DSIZE);
	memcpy(digest, context->state, DSIZE);
}

// print digest to stdout
void MD5Print(MD5Context *context)
{
	PBYTE digest = context->digest;
	for (int i = 0; i < DSIZE; ++i)
	{
		printf("%02hhx", digest[i]);
	}
}

// calculate and print the hash
void printHash(PCBYTE msg, size_t size)
{
	MD5Context context;

	MD5Init(&context);
	MD5Update(&context, msg, size);
	MD5Final(&context);

	printf("MD5(%s) = ", msg);
	MD5Print(&context);
	printf("\n");
}

int main(int argc, char const **argv)
{
	PCBYTE msg = NULL;
	if (argc != 2)
	{
		printf("Usage: %s <MESSAGE>\n", argv[0]);
		return 1;
	}
	msg = argv[1];
	printHash(msg, strlen(msg));
	return 0;
}
