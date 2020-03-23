#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <string.h>
#include <time.h>

char* generatesalt(){
    int index, n;
    time_t t;
	char* salt = malloc(29);
    char algorithm[4] = "$5$";
	const char characters[] =
		"0123456789"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz";
    
    srand(time(&t));
    
	for(int i = 0; i < 24; i++){
		index = rand() % (sizeof(characters) -1);
        salt[i] = characters[index];		
	}
	strcat(salt, "$");
	return strcat(algorithm, salt);
}
int main(){
    printf("%s", generatesalt());
    return 0;
}