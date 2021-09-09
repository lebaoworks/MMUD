#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

void init_random()
{
    srand(time(0));
}

void rand_str(char* address, int len)
{
    static const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    for (int i = 0; i<len; i++)
        address[i] = charset[rand() % (sizeof(charset) - 1)];
}

// Get int in [start, end]
int rand_int(int start, int end)
{
    if (end<start)
        return -1;
    return rand() % (end-start+1);
}