#include <stdio.h>

int main(int argc, char *argv[]) {
    char buffer[15];
    gets(buffer);
    printf("Buffer content: %s\n", buffer);
    return (0);
}