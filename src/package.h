#pragma once

#include <mysql/mysql.h>
#include "stdio.h"
#include "string.h"
#include "stdlib.h"
#include<iostream>

 struct RequestInfo{
    int id;
    char src[100];
    char dest[100];
    int created_at;
};

typedef struct RequestHeader{
    int id;
    int request_id;
    char header_key[100];
    char header_value[1024];
};

int SaveRequestHeader(RequestHeader * h);
int SaveRequestInfo(RequestInfo *req);
void  connection ();