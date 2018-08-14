#include <stdio.h>
#include <crypto/scrypt-jane/scrypt-jane.h>


int main(void) {
	unsigned char digest[16];
	int i;
	scrypt("tt", 2, "salt", 4, 0, 0, 0, digest, 16);
	for (i = 0; i < sizeof(digest); i++)
		printf("%02x, ", digest[i]);
	printf("\n");
	return 0;
}
