
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h> //allows use of uint8_t
#include <time.h>

#define MAX_FILENAME_LENGTH 256
#define BYTE_RANGE 256
#define REQUIRED_ARGUMENTS 5
#define INV_PAIRS 128
#define SECONDARY_OFFSET 128

//Objects
typedef struct {
	int slope;  //default to one for effectively no slope change
	int intercept; //default to zero for no shift
	char cipherIO; //set default to encipher
	char fileName[MAX_FILENAME_LENGTH + 1]; //+1 for Null Terminator
} cipherInfo_t;

// typedef struct set {
// 	int pair[2];
// } pairs_t;

//Global Variables
cipherInfo_t currentCipher = {.slope = 1, .intercept = 0, .cipherIO = 'e', .fileName = {0}}; //see above for default descriptions
//static const pairs_t pairs_list[INV_PAIRS] = { {1, 1}, {3, 43}, {5, 77}, {7, 55}, {9, 57}, {11, 35}, {13, 69}, {15, 111}, {17, 113}, {19, 27}, {21, 61}, {23, 39}, {25, 41}, {27, 19}, {29, 53}, {31, 95}, {33, 97}, {35, 11}, {37, 45}, {39, 23}, {41, 25}, {43, 3}, {45, 37}, {47, 79}, {49, 81}, {51, 123}, {53, 29}, {55, 7}, {57, 9}, {59, 115}, {61, 21}, {63, 63}, {65, 65}, {67, 107}, {69, 13}, {71, 119}, {73, 121}, {75, 99}, {77, 5}, {79, 47}, {81, 49}, {83, 91}, {85, 125}, {87, 103}, {89, 105}, {91, 83}, {93, 117}, {95, 31}, {97, 33}, {99, 75}, {101, 109}, {103, 87}, {105, 89}, {107, 67}, {109, 101}, {111, 15}, {113, 17}, {115, 59}, {117, 93}, {119, 71}, {121, 73}, {123, 51}, {125, 85}, {127, 127}};
static const int keyList[INV_PAIRS] = {1, 171, 205, 183, 57, 163, 197, 239, 241, 27, 61, 167, 41, 19, 53, 223, 225, 139, 173, 151, 25, 131, 165, 207, 209, 251, 29, 135, 9, 243, 21, 191, 193, 107, 141, 119, 249, 99, 133, 175, 177, 219, 253, 103, 233, 211, 245, 159, 161, 75, 109, 87, 217, 67, 101, 143, 145, 187, 221, 71, 201, 179, 213, 127, 129, 43, 77, 55, 185, 35, 69, 111, 113, 155, 189, 39, 169, 147, 181, 95, 97, 11, 45, 23, 153, 3, 37, 79, 81, 123, 157, 7, 137, 115, 149, 63, 65, 235, 13, 247, 121, 227, 5, 47, 49, 91, 125, 231, 105, 83, 117, 31, 33, 203, 237, 215, 89, 195, 229, 15, 17, 59, 93, 199, 73, 51, 85, 255};

//Functions
void setFlags(int argc, char *argv[]) //interpret arguments plus validity checks
{
	if (argc != REQUIRED_ARGUMENTS)
	{
		printf("Invalid Number of Arguments\n");
		exit(0);
	}

	sscanf(argv[1], "%d", &currentCipher.slope);

	if ((currentCipher.slope < 1) || (currentCipher.slope > BYTE_RANGE) || (currentCipher.slope % 2 == 0))
	{
		printf("Invalid Slope\n");
		exit(0);
	}
	sscanf(argv[2], "%d", &currentCipher.intercept);

	if ((currentCipher.intercept < 0) || (currentCipher.intercept > BYTE_RANGE))
	{
		printf("Invalid Intercept\n");
		exit(0);
	}

	sscanf(argv[3], "%c", &currentCipher.cipherIO);

	if ((currentCipher.cipherIO != 'e' && currentCipher.cipherIO != 'd'))
	{
		printf("Invalid Ciphering Operation\n");
		exit(0);
	}

	sscanf(argv[4], "%s", currentCipher.fileName);

	return;
}

int getMultInv(int num)
{
	int index = (num - 1) / 2;
	return keyList[index];
}

void encipher()
{
	FILE *pFile = NULL;
	pFile = fopen(currentCipher.fileName, "rb+");
	fpos_t active_position;

	int size = 0;
	uint8_t byte = 0xFF;
	uint8_t coded_byte = 0x0;

	if (pFile == NULL)
	{
		printf("Unable to open file.\n");
		exit(0);
	}

	//calculate file size
	fseek(pFile, 0, SEEK_END);
	size = ftell(pFile);
	rewind(pFile);

	for (int i = 0; i < size; i++)
	{
		fgetpos(pFile, &active_position);
		fread(&byte, 1, sizeof(byte), pFile);
		//printf("%x", byte);
		coded_byte = (byte * ( currentCipher.slope + (2 * i) ) + currentCipher.intercept + i) % BYTE_RANGE;
		//printf(" %x\t", coded_byte);
		fsetpos(pFile, &active_position);
		fwrite(&coded_byte, sizeof(byte), 1, pFile); //writes to same file
	}
	fclose(pFile);
}
void decipher()
{
	//int inverse = getMultInv(currentCipher.slope + (2 * i)); //get needed inverse for the slope
	FILE *pFile = NULL;
	pFile = fopen(currentCipher.fileName, "rb+");
	fpos_t active_position;

	int size = 0;
	uint8_t byte = 0xFF;
	uint8_t decoded_byte = 0x0;


	if (pFile == NULL)
	{
		printf("Unable to open file.\n");
		exit(0);
	}

	//calculate file size
	fseek(pFile, 0, SEEK_END);
	size = ftell(pFile);
	rewind(pFile);

	for (int i = 0; i < size; i++)
	{
		int inverse = getMultInv( ( currentCipher.slope + (2 * i) ) % BYTE_RANGE); //get needed inverse for the slope
		fgetpos(pFile, &active_position);
		fread(&byte, 1, sizeof(byte), pFile);
		decoded_byte = ((inverse * (byte - currentCipher.intercept - i)) % BYTE_RANGE);
		//printf("%x ", decoded_byte);
		fsetpos(pFile, &active_position);
		fwrite(&decoded_byte, sizeof(byte), 1, pFile); //writes to same file
	}
	fclose(pFile);
}


//Main
int main (int argc, char *argv[]) //argv slope, intercept, cipher, fileName.txt
{
	setFlags(argc, argv);

	if (currentCipher.cipherIO == 'e') //encipher
	{

		encipher();
		printf("%s enciphered.\n", currentCipher.fileName);
	}
	else //decipher
	{
		decipher();
		printf("%s deciphered.\n", currentCipher.fileName);
	}

	return 0;
}


