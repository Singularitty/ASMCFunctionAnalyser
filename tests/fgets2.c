#include <stdio.h>

int main(int argc, char *argv[]) {
    char buffer[15];
    fgets(buffer, 16, stdin);
    printf("Buffer Content: %s\n", buffer);
    return (0);
}