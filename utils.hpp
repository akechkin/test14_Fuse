#ifndef __UTILS__HPP__
#define __UTILS__HPP__

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

#define DBG_LOG(TXT, ...)  printf("[%s]:%d "TXT" \n", __FUNCTION__,__LINE__,##__VA_ARGS__)









#endif