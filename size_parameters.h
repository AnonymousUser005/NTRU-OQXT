#ifndef SIZEPARAMETERS_H
#define SIZEPARAMETERS_H

extern int N_keywords;
extern int N_max_ids;
extern int N_row_ids;
extern int BF_length;

// #define N_HASH 24
// #define N_HASH 48
#define N_HASH 8

// #define MAX_BF_BIN_SIZE 1048576          //20 bits
// #define MAX_BF_BIN_SIZE 16777216         //24 bits
// #define MAX_BF_BIN_SIZE 134217728        //27 bits
// #define MAX_BF_BIN_SIZE 2048             //12 bits
// #define MAX_BF_BIN_SIZE 32                  //5 bits
#define MAX_BF_BIN_SIZE 64                  //6 bits

#endif // SIZEPARAMETERS_H
