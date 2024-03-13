CC = g++
CFLAGS = -I. -I./blake3/ 
CONFIG = -std=c++17 -msse2 -msse -mssse3 -march=native -ffast-math -mavx2 -mfma -maes -lcryptopp -lpthread -lgmpxx -lgmp -lssl -lhiredis -lredis++ -lcrypto -lntl -lm -lrt -fpermissive -fopenmp -Wl,./blake3/libblake3.so,-rpath,/sealusers/user3/redis-plus-plus/build
LD = g++
LDFLAGS = #-pg -no-pie
LIBS = #-lm

oqxt_falcon_setup:  rawdatautil.cpp  bloom_filter.cpp AES_256GCM.c ./falcon-round3/Extra/c/shake.c ./falcon-round3/Extra/c/common.c ./falcon-round3/Extra/c/keygen.c ./falcon-round3/Extra/c/fft.c ./falcon-round3/Extra/c/fpr.c  ./falcon-round3/Extra/c/vrfy.c ./falcon-round3/Extra/c/codec.c ./falcon-round3/Extra/c/sign.c ./falcon-round3/Extra/c/rng.c oqxt-falcon_setup.cpp 
	$(CC) -g -o oqxt_falcon_setup  rawdatautil.cpp  bloom_filter.cpp AES_256GCM.c ./falcon-round3/Extra/c/shake.c ./falcon-round3/Extra/c/common.c ./falcon-round3/Extra/c/keygen.c ./falcon-round3/Extra/c/fft.c ./falcon-round3/Extra/c/fpr.c ./falcon-round3/Extra/c/vrfy.c ./falcon-round3/Extra/c/codec.c ./falcon-round3/Extra/c/sign.c ./falcon-round3/Extra/c/rng.c ./blake3/blake_hash.cpp oqxt-falcon_setup.cpp  $(CONFIG)

oqxt_falcon_search:  rawdatautil.cpp  bloom_filter.cpp AES_256GCM.c ./falcon-round3/Extra/c/shake.c ./falcon-round3/Extra/c/common.c ./falcon-round3/Extra/c/keygen.c ./falcon-round3/Extra/c/fft.c ./falcon-round3/Extra/c/fpr.c  ./falcon-round3/Extra/c/vrfy.c ./falcon-round3/Extra/c/codec.c ./falcon-round3/Extra/c/sign.c ./falcon-round3/Extra/c/rng.c oqxt-falcon_search.cpp 
	$(CC) -g -o oqxt_falcon_search  rawdatautil.cpp  bloom_filter.cpp AES_256GCM.c ./falcon-round3/Extra/c/shake.c ./falcon-round3/Extra/c/common.c ./falcon-round3/Extra/c/keygen.c ./falcon-round3/Extra/c/fft.c ./falcon-round3/Extra/c/fpr.c ./falcon-round3/Extra/c/vrfy.c ./falcon-round3/Extra/c/codec.c ./falcon-round3/Extra/c/sign.c ./falcon-round3/Extra/c/rng.c ./blake3/blake_hash.cpp oqxt-falcon_search.cpp  $(CONFIG)

clean:
	rm -rf *.o *.gch eidxdb.csv bloom_filter.dat

