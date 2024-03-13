#ifndef UTILS_H
#define UTILS_H


#include <iostream>
#include <cstring>
#include <string>
#include <sstream>
#include <fstream>
#include <iomanip>
#include <vector>
#include <set>
#include <map>
#include <bitset>
#include <random>
#include <algorithm>
#include <functional>
#include <stdexcept>
#include <cmath>
#include <cstdio>
#include <unistd.h>
#include <cstdlib>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <bits/stdc++.h>


// const int N_l = 71;
// const int m_l = 568;
// const int mb_l = 142;
// const int q_l  = 64;

// const int N_l = 36;
// const int m_l = 216;
// const int mb_l = 72;
// const int q_l  = 16;

// const int N_l = 512;
// const int m_l = 17408;
// const int mb_l = 1024;
// const long int q_l  = 4294967296;

const int N_l = 512;
const int m_l = 10240;
const int mb_l = 1024;
// const long int q_l  = 1048576;
const long int q_l  = 12289;
#define P_l 256 

// #define q 11
// #define n 7
// #define mb 2
// #define q 11
// #define p 3
// #define k1 ceil(log2(q))
// // #define w 8
// unsigned int nk = n * k1;



// #define P_l 3
// #define P_l 65536    ////q=2^30
// #define P_l 256         //q=2^20
const int k1_l = ceil(log2(q_l));
const int nk_l = N_l * k1_l;   //w acc to paper
const int nk_v = N_l * (k1_l-1);

// std::vector<std:: vector<int>> multiply(std:: vector<std:: vector<int>> &A , std:: vector<std:: vector<int>> &B);
// int GenTrapdoor(unsigned char **A_b, unsigned char **H, unsigned char **T, unsigned char **z);
// int subGaussian(unsigned char **R);


#endif