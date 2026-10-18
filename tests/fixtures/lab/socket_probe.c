/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#include <stdio.h>
#include <sys/socket.h>

int main(void)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    printf("socket %d\n", fd);
    return 0;
}
