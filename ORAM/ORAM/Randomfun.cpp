#include <stdlib.h>
#include <conio.h>
#include <time.h>
int getRandomnum(int num)
{

	srand((unsigned)time(NULL));
	int rannum=rand() % num;
	return rannum;
}