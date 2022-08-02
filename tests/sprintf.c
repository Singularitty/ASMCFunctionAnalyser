#include <stdio.h>

int main(int argc, char *argv[]) {
    char buffer[15];
    char *str = "Buffer Overflow String";
    sprintf(buffer, "%s", str);
    printf("Buffer Content: %s\n",buffer);
    return (0);
}