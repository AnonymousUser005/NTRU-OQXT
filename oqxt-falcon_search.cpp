#include "oqxt-falcon_search.h"

// string rawdb_file = "widxdb_small2.csv";
string rawdb_file = "db6k.dat";
string eidxdb_file = "eidxdb_small2.csv";
string bloomfilter_file = "bloom_filter.dat";//Bloom filter file

sw::redis::ConnectionOptions connection_options;
sw::redis::ConnectionPoolOptions pool_options;


unsigned char **BF;

unsigned char *UIDX;


//db6k.dat
int N_keywords = 6043;
int N_max_ids = 9690;
int N_row_ids = N_max_ids;
int N_words = N_keywords;
int N_max_id_words = 1809;
// int N_kw_id_max = 1108;
int N_kw_id_max = 80901;
int N_threads = 16;


//widxdb_small2.csv
// int N_keywords = 5;
// int N_max_ids = 31;
// int N_row_ids = N_max_ids;
// int N_words = N_keywords;
// int N_max_id_words = 17;
// // int N_kw_id_max = 41;
// int N_threads = 16;



int sym_block_size = 16;
int hash_block_size = 64;
int bhash_block_size = 64;
int bhash_in_block_size = 40;




//IVs and Keys for AES-256 GCM encryption
unsigned char iv_ks[16], iv_ki[16], iv_r[16], iv_ec[16], iv_ke[16]; // iv_kx[16], iv_kz[16], iv_kt[16], iv_stag[16];
unsigned char tag_r[100], tag_ec[100], tag_kz[100], tag_ks[100], tag_ki[100], tag_kx[100], tag_kt[100],tag_stag[100]; 
unsigned char aad[16]="00000002";
int ke, kw, ka, kec, kt, k_stag, k_stag_query, k_stag_TSetRetrieve;
int kw_dec;

vector<int> kid_enc_vec, kid_dec_vec, kr_enc_vec;

unsigned char iv_kt[16] = {0x56,0x37,0xca,0x94,0xd5,0xe0,0xad,0x62,0x73,0x7c,0xba,0x48,0x8d,0x2d,0x4d,0xde};
unsigned char iv_stag[16] = {0x56,0x37,0xca,0x94,0xd5,0xe0,0xad,0x62,0x73,0x7c,0xba,0x48,0x8d,0x2d,0x4d,0xde};
unsigned char iv_kx[16] = {0x56,0x37,0xca,0x94,0xd5,0xe0,0xad,0x62,0x73,0x7c,0xba,0x48,0x8d,0x2d,0x4d,0xde};
unsigned char iv_kz[16] = {0x56,0x37,0xca,0x94,0xd5,0xe0,0xad,0x62,0x73,0x7c,0xba,0x48,0x8d,0x2d,0x4d,0xde};





// unsigned char KS[32]; //For PRF F
// unsigned char KZ[32]; //For PRF F_q'
// unsigned char KI[32]; //For PRF F_q
// unsigned char KX[32]; //For PRF F_q
// unsigned char KR[32]; //For generating A
// unsigned char KT[32]; //For TSet (encrypting stag)



unsigned char KS[32] = {0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4};
unsigned char KI[32] = {0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4};
unsigned char KZ[32] = {0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4};
unsigned char KX[32] = {0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4};
unsigned char KR[32] = {0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4};
unsigned char KT[32] = {0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4};



const char* KS1 = reinterpret_cast<const char *> (KS);
const char* KZ1 = reinterpret_cast<const char *> (KZ);
const char* KI1 = reinterpret_cast<const char *> (KI);
const char* KX1 = reinterpret_cast<const char *> (KX);
const char* KR1 = reinterpret_cast<const char *> (KR);
const char* KT1 = reinterpret_cast<const char *> (KT);


//For Bloom Filter Implementation
unsigned char* GL_BLOOM_MSG = new unsigned char[40*N_max_id_words];
unsigned char* GL_BLOOM_DGST = new unsigned char[64*N_max_id_words];
unsigned char* GL_HASH_DGST = new unsigned char[64*N_max_id_words];
unsigned char* GL_HASH_MSG = new unsigned char[32*N_max_id_words];
unsigned char* GL_BLM_MSG = new unsigned char[40];
unsigned char* GL_BLM_DGST = new unsigned char[64];

unsigned char* GL_MGDB_RES = new unsigned char[N_max_id_words*49]; 
unsigned char* GL_MGDB_BIDX = new unsigned char[N_max_id_words*2];
unsigned char* GL_MGDB_JIDX = new unsigned char[N_max_id_words*2];
unsigned char* GL_MGDB_LBL = new unsigned char[N_max_id_words*12];

unsigned char* MGDB_RES;
unsigned char* MGDB_BIDX;
unsigned char* MGDB_JIDX;
unsigned char* MGDB_LBL;



// // ---------------------------------------------------------------------------------------------------------------------------------- // //



int Sys_Init()
{
    
    connection_options.host = "127.0.0.1";  // Required.
    BloomFilter_Init(BF);

    return 0;
}

int Sys_Clear()
{
    BloomFilter_Clean(BF);

    return 0;
}



//For Falcon random plynomial generation (HashToPoint)
static void *
xmalloc(size_t len)
{
	void *buf;

	if (len == 0) {
		return NULL;
	}
	buf = malloc(len);
	if (buf == NULL) {
		fprintf(stderr, "memory allocation error\n");
		exit(EXIT_FAILURE);
	}
	return buf;
}



int SHA3_HASH(blake3_hasher *hasher,unsigned char *msg, unsigned char *digest)
{
    Blake3(hasher,digest,msg);
    return 0;
}


int SHA3_HASH_K(blake3_hasher *hasher,unsigned char *msg, unsigned char *digest)
{
    Blake3_K(hasher,digest,msg);
    return 0;
}


int BLOOM_HASH(unsigned char *msg, unsigned char *digest)
{
        blake3_hasher hasher;
        blake3_hasher_init(&hasher);


        ::memset(GL_BLOOM_MSG,0x00,bhash_in_block_size);
        ::memset(GL_BLOOM_DGST,0x00,hash_block_size);
        for(int i=0;i<N_HASH;i++){ //keep this operation here
            ::memcpy(GL_BLOOM_MSG+(40*i),msg,32);
            GL_BLOOM_MSG[40*i+39] = (i & 0xFF);
        }

    
        SHA3_HASH_K(&hasher,GL_BLOOM_MSG,GL_BLOOM_DGST);
        ::memcpy(digest,GL_BLOOM_DGST,hash_block_size);
        
    return 0;
}


int FPGA_HASH(unsigned char *msg, unsigned char *digest)
{
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    
    ::memset(GL_HASH_DGST,0x00,hash_block_size);
    ::memcpy(GL_HASH_MSG,msg,sym_block_size);

    SHA3_HASH(&hasher,GL_HASH_MSG,GL_HASH_DGST);

    ::memcpy(digest,GL_HASH_DGST,hash_block_size);

    return 0;
}

int MGDB_QUERY(unsigned char *RES, unsigned char *BIDX, unsigned char *JIDX, unsigned char *LBL)
{
    ::memcpy(GL_MGDB_BIDX,BIDX,(N_threads * 2));
    ::memcpy(GL_MGDB_JIDX,JIDX,(N_threads * 2));
    ::memcpy(GL_MGDB_LBL,LBL,(N_threads * 12));
    ::memset(GL_MGDB_RES,0x00,(N_threads * 49));

    auto redis = Redis("tcp://127.0.0.1:6379");
    // Redis redis_thread(connection_options, pool_options);
        
    string s = HexToStr(GL_MGDB_BIDX,2) + HexToStr(GL_MGDB_JIDX,2) + HexToStr(GL_MGDB_LBL,12);
    
    auto val = redis.get(s);
    unsigned char *t_res = reinterpret_cast<unsigned char *>(val->data());
    DB_StrToHex49(GL_MGDB_RES,t_res);

    ::memcpy(RES,GL_MGDB_RES,(49));

    return 0;
}




int TSet_GetTag(unsigned char *word, unsigned char *stag)
{
    ::memset(stag,0x00,32);
    // if(!PKCS5_PBKDF2_HMAC_SHA1(KT1, strlen(KT1),NULL,0,1000,32,KT))
    // {
    //     printf("Error in key generation\n");
    //     exit(1);
    // }
    // while(!RAND_bytes(iv_kt,sizeof(iv_kt)));

    k_stag_query = encrypt(word, sizeof(stag)/sizeof(*stag), aad, sizeof(aad), KT, iv_kt, stag, tag_kt);
    return 0;
}

int TSet_Retrieve(unsigned char *stag,unsigned char *tset_row, int *n_ids_tset)
{
    unsigned char *stagi;
    unsigned char *stago;
    unsigned char *hashin;
    unsigned char *hashout;
    unsigned char *TV;
    
    
    stagi = new unsigned char[32*N_max_id_words];
    stago = new unsigned char[32*N_max_id_words];
    hashin = new unsigned char[32*N_max_id_words];
    hashout = new unsigned char[64*N_max_id_words];
    TV = new unsigned char[48*N_max_id_words];
    UIDX = new unsigned char[16*N_max_ids];



    unsigned char TENTRY[61*N_max_id_words];
    unsigned char TVAL[49*N_max_id_words];
    unsigned char TBIDX[2*N_max_id_words];
    unsigned char TJIDX[2*N_max_id_words];
    unsigned char TLBL[12*N_max_id_words];
    unsigned char HLBL[12*N_max_id_words];


    unsigned int *FreeB;
    int bidx=0;
    int len_freeb = 65536;
    int freeb_idx = 0;
    bool BETA = 0;

    unsigned char *stagi_local;
    unsigned char *stago_local;
    unsigned char *hashin_local;
    unsigned char *hashout_local;

    unsigned char * TV_curr;

    unsigned char *T_RES;
    unsigned char *T_BIDX;
    unsigned char *T_JIDX;
    unsigned char *T_LBL;

    unsigned char *local_t_res;
    unsigned char *local_t_bidx;
    unsigned char *local_t_jidx;
    unsigned char *local_t_lbl;
 
    unsigned char *local_t_res_word;
    unsigned char *local_t_bidx_word;
    unsigned char *local_t_jidx_word;
    unsigned char *local_t_lbl_word;
    unsigned char *local_hashout_word;

    T_RES = new unsigned char[49*N_max_id_words];
    T_BIDX = new unsigned char[2*N_max_id_words];
    T_JIDX = new unsigned char[2*N_max_id_words];
    T_LBL = new unsigned char[12*N_max_id_words];

    int rcnt = 0;

    ::memset(stagi,0x00,32*N_max_id_words);
    ::memset(stago,0x00,32*N_max_id_words);
    ::memset(hashin,0x00,32*N_max_id_words);
    ::memset(hashout,0x00,64*N_max_id_words);
    ::memset(TV,0x00,48*N_max_id_words);
    ::memset(UIDX,0x00,16*N_max_ids);

    ::memset(TVAL,0x00,49*N_max_id_words);
    ::memset(TJIDX,0x00,2*N_max_id_words);

    FreeB = new unsigned int[len_freeb];

    for(int bc=0;bc<len_freeb;++bc){
        FreeB[bc] = 0;
    }

   

    //Fill stagi array
    stagi_local = stagi;
    for(int nword = 0;nword < N_words;++nword){
        for(int nid=0; nid<N_threads; nid++){
            // stagi_local[0] >>= 16;
            stagi_local[0] = ((nword*N_threads)+nid) & 0xFF;
            stagi_local += EVP_MAX_BLOCK_LENGTH;
        }
    }
    stagi_local = stagi;

    //PRF of stag and if
    // const char* stag1 = reinterpret_cast<const char *> (stag);
    // if(!PKCS5_PBKDF2_HMAC_SHA1(stag1, strlen(stag1),NULL,0,1000,32,stag))
    // {
    //     printf("Error in key generation\n");
    //     exit(1);
    // }
    // while(!RAND_bytes(iv_stag,sizeof(iv_stag)));


    stagi_local = stagi;
    hashin_local = hashin;
    for(int nword = 0;nword < N_words;++nword){
        k_stag_TSetRetrieve = encrypt(stagi_local, sizeof(hashin_local)/sizeof(hashin_local[nword]), aad, sizeof(aad), stag, iv_stag, hashin_local, tag_stag);
       
        stagi_local += EVP_MAX_BLOCK_LENGTH;
        hashin_local += EVP_MAX_BLOCK_LENGTH;
    }
    stagi_local = stagi;
    hashin_local = hashin;

  

    //Compute Hash
    hashin_local = hashin;
    hashout_local = hashout;
    for(int nword = 0;nword < N_words;++nword){
        FPGA_HASH(hashin_local,hashout_local);
        hashin_local += EVP_MAX_BLOCK_LENGTH;
        hashout_local += hash_block_size;
    }
    hashin_local = hashin;
    hashout_local = hashout;

    
    TV_curr = TV;

    ::memset(T_RES,0x00,49*N_max_id_words);
    ::memset(T_BIDX,0x00,2*N_max_id_words);
    ::memset(T_JIDX,0x00,2*N_max_id_words);
    ::memset(T_LBL,0x00,12*N_max_id_words);

    local_t_res = T_RES;
    local_t_bidx = T_BIDX;
    local_t_jidx = T_JIDX;
    local_t_lbl = T_LBL;
    
    while(!BETA){

        local_hashout_word = hashout_local;
        
        local_t_res_word = local_t_res;
        local_t_bidx_word = local_t_bidx;
        local_t_jidx_word = local_t_jidx;
        local_t_lbl_word = local_t_lbl;

        for(unsigned int ni=0;ni<N_threads;++ni){
            ::memcpy(local_t_bidx,hashout_local,2);

            freeb_idx = ((local_t_bidx[1] << 8) + local_t_bidx[0]);

            bidx = (FreeB[freeb_idx]++);
            local_t_jidx[0] =  bidx & 0xFF;
            local_t_jidx[1] =  (bidx >> 8) & 0xFF;

            ::memcpy(local_t_lbl,hashout_local+2,12);
            
            local_t_bidx += 2;
            local_t_jidx += 2;
            local_t_lbl += 12;
            hashout_local +=64;
        }
        
        string s = HexToStr(local_t_bidx_word,2) + HexToStr(local_t_jidx_word,2) + HexToStr(local_t_lbl_word,12);
        // std::cout << "s = " << s << endl;

        MGDB_QUERY(local_t_res,local_t_bidx_word,local_t_jidx_word,local_t_lbl_word);
      
        for(unsigned int ni=0;ni<N_threads;++ni){
          ::memcpy(TVAL,local_t_res,49);
          BETA = TVAL[0] ^ local_hashout_word[15];

          for(int i=0;i<48;++i){
              TV_curr[i] = local_hashout_word[16+i] ^ TVAL[i+1];
          }

          rcnt++;
          if(BETA == 0x01) break;

          TV_curr += 48;
          local_t_res += 49;

          local_hashout_word += 64;
        }
    }
    
    
    *n_ids_tset = rcnt;
   
    // std::cout << std::endl;

    ::memcpy(tset_row,TV,48*rcnt);
    // for(int i=0; i<rcnt; i++)
    // {
    //     cout << DB_HexToStr(tset_row+48*i) << endl;
    // }

   

    delete [] stagi;
    delete [] stago;
    delete [] hashin;
    delete [] hashout;
    delete [] TV;

    delete [] FreeB;

    delete [] T_RES;
    delete [] T_BIDX;
    delete [] T_JIDX;
    delete [] T_LBL;
   
    return 0;
}


int FPGA_BLOOM_HASH(unsigned char *msg, unsigned char *digest)
{

    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    
    ::memset(GL_BLM_MSG,0x00,bhash_in_block_size);
    ::memset(GL_BLM_DGST,0x00,bhash_block_size);
    for(int i=0;i<N_HASH;i++){ //keep this operation here
        ::memcpy(GL_BLM_MSG+(40*i),msg,32);
        GL_BLM_MSG[40*i+39] = (i & 0xFF);
    }

    SHA3_HASH_K(&hasher,GL_BLM_MSG,GL_BLM_DGST);

    ::memcpy(digest,GL_BLM_DGST,bhash_block_size);

    return 0;
}


unsigned int BFIdxConv(unsigned char *hex_arr,unsigned int n_bits)
{
    unsigned int idx_val = 0;
    unsigned int n_bytes = n_bits/8;
    unsigned int n_bits_rem = n_bits%8;
    unsigned char tmp_char;
    
    for(unsigned int i=0;i<n_bytes;++i){
        idx_val = (idx_val << 8) | hex_arr[i];
    }

    if(n_bits_rem != 0){
        tmp_char = hex_arr[n_bytes];
        tmp_char = tmp_char >> (8 - n_bits_rem);
        idx_val = (idx_val << n_bits_rem) | tmp_char;
    }

    return idx_val;
}


static void
mk_rand_poly_oqxt(prng *p, fpr *f, unsigned logn)
{
	size_t u, n;

	n = (size_t)1 << logn;
	for (u = 0; u < n; u ++) {
		int32_t x;
		
		x = prng_get_u8(p);
		x = (x << 8) + prng_get_u8(p);
		x &= 0x3FF;
		f[u] = fpr_of(x - 512);
	}
}


int EDB_Search(unsigned char *query_str, int NWords)   
{

    unsigned char Q1[16];
   
    unsigned char *stag;
    unsigned char *tset_row;
    unsigned char *W;
    unsigned char *ID;
   
    unsigned char *WC;
    unsigned char *R;
    unsigned char *EC;
    unsigned char *Yid;
    unsigned char *XWE;
    unsigned char *XIDE;
    unsigned char *dec_pt;
    unsigned char *dec_pt_id;
    unsigned char *bhash;

    int* T;           
    int* ZW;
    uint8_t* YID;
    unsigned char *XW;         
    unsigned char *XID;
    unsigned char *XW_poly;         
    unsigned char *XID_poly;
    unsigned char *XToken;    
    unsigned char *XTAG;    
    
   

    stag = new unsigned char[32*N_max_id_words];
    tset_row = new unsigned char[48*N_max_id_words];
    W = new unsigned char[16*strlen((char *)query_str)];            //Holds the keyword
    ID = new unsigned char[16*N_max_id_words];                 //Maximum number of IDs in a row
    WC = new unsigned char[16*N_max_id_words];                 //IDs with counter value(for computing randomness R)
    R = new unsigned char[N_max_id_words*EVP_MAX_BLOCK_LENGTH];          //Random value for generating trapdoor matrix -- used in generating A
    EC = new unsigned char[EVP_MAX_BLOCK_LENGTH*N_max_id_words];                           //Encrypted IDs
    Yid = new unsigned char[16*N_l*m_l];
    XWE = new unsigned char[N_max_id_words*EVP_MAX_BLOCK_LENGTH];        
    dec_pt = new unsigned char[N_max_id_words*EVP_MAX_BLOCK_LENGTH];        
    XIDE = new unsigned char[N_max_id_words*EVP_MAX_BLOCK_LENGTH];       //Encrypt IDs using AES-256
    dec_pt_id = new unsigned char[N_max_id_words*EVP_MAX_BLOCK_LENGTH];        
    XW = new unsigned char [N_max_id_words*EVP_MAX_BLOCK_LENGTH];    //XW for LWR sample generation
    XID = new unsigned char [N_max_id_words*EVP_MAX_BLOCK_LENGTH]; 
    XToken = new unsigned char [N_max_id_words*EVP_MAX_BLOCK_LENGTH];
    XTAG = new unsigned char [N_max_id_words*EVP_MAX_BLOCK_LENGTH];
    T = new int[16*m_l*N_max_id_words];                         //secret key of Falcon for signature generation
    ZW = new int[16*m_l*N_max_id_words];                        //public-key for verification of signature
    YID = new uint8_t [32*N_max_id_words];
    bhash = new unsigned char[64*N_HASH];
    XW_poly = new unsigned char [N_max_id_words*EVP_MAX_BLOCK_LENGTH];    
    XID_poly = new unsigned char [N_max_id_words*EVP_MAX_BLOCK_LENGTH]; 
    UIDX = new unsigned char[16*N_max_ids];


   
    stringstream ss;

    string rawdb_row;
    vector<string> rawdb_data;
    string rawdb_row_current;
    string s;


    bool idx_in_set = false;
    int nmatch = 0;
    unsigned int bfidx = 0;

    unsigned int** bf_n_indices;

    bf_n_indices = new unsigned int *[N_HASH];
    for(unsigned int i=0;i<N_HASH;++i){
        bf_n_indices[i] = new unsigned int [NWords];
    }


     
    ::memset(stag,0x00,32*N_max_id_words);
    ::memset(tset_row,0x00,48*N_max_id_words);
    ::memset(W,0x00,16*strlen((char *)query_str));
    ::memset(ID,0x00,16*N_max_id_words);
    ::memset(WC,0x00,16*N_max_id_words);
    ::memset(R,0x00,N_max_id_words*EVP_MAX_BLOCK_LENGTH);
    ::memset(EC,0x00,N_max_id_words*EVP_MAX_BLOCK_LENGTH);
    ::memset(XWE,0x00,N_max_id_words*EVP_MAX_BLOCK_LENGTH);
    ::memset(dec_pt,0x00,N_max_id_words*EVP_MAX_BLOCK_LENGTH);
    ::memset(XIDE,0x00,N_max_id_words*EVP_MAX_BLOCK_LENGTH);
    ::memset(dec_pt_id,0x00,N_max_id_words*EVP_MAX_BLOCK_LENGTH);
    ::memset(Yid, 0x00, 16*N_l*m_l);
    ::memset(XW,0x00, N_max_id_words*EVP_MAX_BLOCK_LENGTH);
    ::memset(XID,0x00, N_max_id_words*EVP_MAX_BLOCK_LENGTH);
    ::memset(XToken,0x00, N_max_id_words*EVP_MAX_BLOCK_LENGTH);
    ::memset(XTAG,0x00, N_max_id_words*EVP_MAX_BLOCK_LENGTH);
    ::memset(T,0x00,16*m_l*N_max_id_words);
    ::memset(ZW,0x00,16*m_l*N_max_id_words);
    ::memset(YID,0x00,32*N_max_id_words);
    ::memset(bhash,0x00,64*N_HASH);
    ::memset(XW_poly,0x00, N_max_id_words*EVP_MAX_BLOCK_LENGTH);
    ::memset(XID_poly,0x00,N_max_id_words*EVP_MAX_BLOCK_LENGTH);
    ::memset(UIDX,0x00,16*N_max_ids);




    
    unsigned char *id_local = ID;
    unsigned char *r_local = R;
    unsigned char *wc_local = WC;
    unsigned char *w_local = W;
    unsigned char *xwe_local = XWE;
    unsigned char *dec_pt_local = dec_pt;
    unsigned char *dec_pt_local_id = dec_pt_id;
    unsigned char *xide_local = XIDE;
    unsigned char *ec_local = EC;
    unsigned char *xw_local = XW;
    unsigned char *xid_local = XID;
    unsigned char *xw_local_poly = XW_poly;
    unsigned char *xid_local_poly = XID_poly;
    unsigned char *xtoken_local = XToken;
    int *t_local = T;
    int *zw_local = ZW;
    uint8_t *yid_local = YID;
    unsigned char *tset_row_local = tset_row;
    unsigned char *xtg_local = nullptr;
    unsigned char *uidx_local = UIDX;


    ::memcpy(Q1,query_str,16);

    unsigned char *local_s;

    int n_rows = 0;
    int n_row_ids = 0;
    int n_ids_tset = 0;

    // Sys_Init();
    
    // std::cout << "Entered Search 1.0" << std::endl;
    
    TSet_GetTag(Q1,stag);
    // std::cout << DB_HexToStr_N(Q1,16)  << endl << DB_HexToStr_N(stag,16) << std::endl;

    TSet_Retrieve(stag,tset_row,&n_ids_tset);
    // std::cout << "TSet_Retrieve done" << std::endl;

    cout << "N IDs TSet: " << n_ids_tset << endl;
    
    for(int i=0; i<N_max_id_words; ++i)
    {
        ::memcpy(WC+(i*16),Q1,16);
    }

	
    //Copy all query keywords except first
    ::memcpy(W,query_str+16,(16*NWords));


    //Generating Public key, Private Key and Signature

    /* Computing randomness r to pass to keygen algorithm */

    // (append w || counter)
    wc_local = WC;
    for(int nword=0; nword<n_ids_tset; ++nword)
    {
        ::memcpy(wc_local,W,16);
        wc_local += 16;
    }
    wc_local = WC;
    
    /* PRF to compute r  */      
    // if(!PKCS5_PBKDF2_HMAC_SHA1(KZ1, strlen(KZ1),NULL,0,1000,32,KZ))
    // {
    //     printf("Error in key generation\n");
    //     exit(1);
    // }
    // while(!RAND_bytes(iv_kz,sizeof(iv_kz)));

    auto start_time = std::chrono::high_resolution_clock::now();
  
    unsigned int count_wc = 1;
    unsigned int count_wc_local = 0;
    r_local = R;
    wc_local = WC;
    unsigned char pt[16];
    for(unsigned int nword=0; nword<n_ids_tset; nword++)
    {
        count_wc_local = count_wc;
        *(wc_local+0) = count_wc_local & 0xFF;
        count_wc_local >>= 8;
        *(wc_local+1) = count_wc_local & 0xFF;
        count_wc++;


        int kr = encrypt(wc_local, sizeof(r_local)/sizeof(r_local[nword]), aad, sizeof(aad), KZ, iv_kz, r_local, tag_kz);
        kr_enc_vec.push_back(kr);
        
        // cout << DB_HexToStr_N(r_local,32) << std::endl;
        
        wc_local += 16;
        r_local += EVP_MAX_BLOCK_LENGTH;
    }
    r_local = R;
    wc_local = WC;

    // std::cout << std::endl;


    /* For Key and Signature generation */
    
    for(unsigned int nword=0; nword<n_ids_tset; nword++)
    {
        /* Key Generation */
        
        size_t n_keygen;
        size_t tlen_keygen = 90112;
        size_t tlen_sign = 178176;
        unsigned logn_keygen = 4;
        int8_t *f, *g, *F, *G;
        uint16_t *h, *hm, *h2, *hm2, *h_mont;
        int16_t *sig_keygen, *s1_keygen;
        uint8_t *tt_keygen, *tt_sign, *temp_sign;
        inner_shake256_context sc_keygen;
        fpr *expanded_key;              //serves as T (secret key); fpr -> uint_64 type
        int i;


        fflush(stdout);

        inner_shake256_init(&sc_keygen);
        inner_shake256_inject(&sc_keygen, r_local, sizeof r_local);
        inner_shake256_flip(&sc_keygen);


        temp_sign = xmalloc(tlen_sign);
        h_mont = (uint16_t *)temp_sign;

        n_keygen = (size_t)1 << logn_keygen;
        f = xmalloc(tlen_keygen);
        g = f + n_keygen;
        F = g + n_keygen;
        G = F + n_keygen;
        h = (uint16_t *)(G + n_keygen);
        h2 = h + n_keygen;
        hm = h2 + n_keygen;
        sig_keygen = (int16_t *)(hm + n_keygen);
        s1_keygen = sig_keygen + n_keygen;
        tt_keygen = (uint8_t *)(s1_keygen + n_keygen);
        tt_sign = (uint8_t *)(s1_keygen + n_keygen);
        if (logn_keygen == 1) {
            tt_keygen += 4;
            tt_sign += 4;
        }
        for (i = 0; i < 12; i ++) {
            Zf(keygen)(&sc_keygen, f, g, F, G, h, logn_keygen, tt_keygen);
        }


        //Public key h in NTT-Montgomery Form
        ::memcpy(h_mont, h, n_keygen * sizeof *h_mont);
        Zf(to_ntt_monty)(h_mont, logn_keygen);

         
         
        
        ::memset(XToken,0x00, N_max_id_words*EVP_MAX_BLOCK_LENGTH);

        //Generate xtoken
        for(unsigned int n1=0; n1<NWords; ++n1) // for every keyword
        {
            double xtoken_temp;

            ::memset(XW,0x00, N_max_id_words*EVP_MAX_BLOCK_LENGTH);
            //Generate XW (PRF output of KX and W)
            // if(!PKCS5_PBKDF2_HMAC_SHA1(KX1, strlen(KX1),NULL,0,1000,32,KX))
            // {
            //     printf("Error in key generation\n");
            //     exit(1);
            // }
            // while(!RAND_bytes(iv_kx,sizeof(iv_kx)));

    
            xw_local = XW;
            w_local = W;
            kw = encrypt(w_local, sizeof(xw_local)/sizeof(xw_local[n1]), aad, sizeof(aad), KX, iv_kx, xw_local, tag_kx);
            xw_local = XW;
            w_local = W;

            // cout << DB_HexToStr_N(xw_local,32) << " ----- " << std::endl;


            //Generate rand+om polynomial wrt XW from Falcon specifications
            inner_shake256_context sc_xw;
            size_t tlen_xw = 90112;
            int8_t *f_xw = xmalloc(tlen_xw);
            int8_t logn_xw = 4;
            fpr *xw_fpr = (fpr*) f_xw;
            prng p;


            inner_shake256_init(&sc_xw); 		                            //Initialises the array A to all 0
            inner_shake256_inject(&sc_xw, (const uint8_t*) xw_local, sizeof xw_local);	    // injects msg to context sc
            inner_shake256_flip(&sc_xw);

            Zf(prng_init)(&p, &sc_xw);                                  
            mk_rand_poly_oqxt(&p, xw_fpr, logn_xw);     


            //Xtoken Computation
            Zf(FFT)(xw_fpr, logn_xw);
            Zf(FFT)((fpr*) h_mont, logn_keygen);
            Zf(poly_mul_fft)(xw_fpr, (fpr*) h_mont, logn_xw);
            xtoken_temp = floor(int32_t(xw_fpr) * P_l/q_l);
            ::memcpy(xtoken_local,  &xtoken_temp, 32);
            // ::memcpy(xtoken_local, (unsigned char*) xw_fpr, 32);

            // cout << DB_HexToStr_N(xtoken_local,32) << std::endl;
            
            xtoken_local += EVP_MAX_BLOCK_LENGTH;
        }
        xtoken_local = XToken;

        std::cout << std::endl;

    }

    ::memcpy(YID,tset_row_local,32);

    yid_local = YID;
    for(int i=0;i<n_ids_tset;++i){
        ::memcpy(yid_local,YID,32);
        yid_local += 32;
    }
    yid_local = YID;
    // std::cout << std::endl;

    
    yid_local = YID;
    for(int i=0;i<n_ids_tset;++i)
    {
        ::memset(XTAG,0x00, N_max_id_words*EVP_MAX_BLOCK_LENGTH);
        ::memset(EC,0x00,N_max_id_words*EVP_MAX_BLOCK_LENGTH);

        // ::memcpy(YID,tset_row_local,32);
        ::memcpy(EC,tset_row_local+32,16);

        // yid_local = YID;
        // for(int i=0;i<NWords;++i){//This should run till row_len
        //     ::memcpy(yid_local,YID,32);
        //     cout << DB_HexToStr_N(yid_local,32) << std::endl;
        //     yid_local += 64;
        // }
        // yid_local = YID;

        if(NWords == 0){
            ::memcpy(ec_local,EC,32);
            ec_local +=EVP_MAX_BLOCK_LENGTH;
            ++nmatch;
            std::cout << "Yes" << std::endl;
        }
        else {
            xtg_local = XTAG;
            xtoken_local = XToken;
            yid_local = YID;
            for(unsigned int n1=0; n1<NWords; ++n1) // for every keyword
            {
        
                double xtg_temp;
                inner_shake256_context sc_yid;
                size_t tlen_yid = 90112;
                int8_t *f_yid = xmalloc(tlen_yid);
                int8_t logn_yid = 4;
            
                fpr *yid_fpr = (fpr*) f_yid;
                prng p_yid;

                inner_shake256_init(&sc_yid); 		                            //Initialises the array A to all 0
                inner_shake256_inject(&sc_yid, yid_local, sizeof yid_local);	// injects msg to context sc
                inner_shake256_flip(&sc_yid);

                
                Zf(prng_init)(&p_yid, &sc_yid);                                  
                mk_rand_poly_oqxt(&p_yid, yid_fpr, logn_yid);                         


                inner_shake256_context sc_xtoken;
                size_t tlen_xtoken = 90112;
                int8_t *f_xtoken = xmalloc(tlen_xtoken);
                int8_t logn_xtoken = 4;
            
                fpr *xtoken_fpr = (fpr*) f_xtoken;
                prng p_xtoken;

                inner_shake256_init(&sc_xtoken); 		                            //Initialises the array A to all 0
                inner_shake256_inject(&sc_xtoken, xtoken_local, sizeof xtoken_local);	// injects msg to context sc
                inner_shake256_flip(&sc_xtoken);

            
                
                Zf(prng_init)(&p_xtoken, &sc_xtoken);                                  
                mk_rand_poly_oqxt(&p_xtoken, xtoken_fpr, logn_xtoken);        


                Zf(FFT)(yid_fpr, logn_yid);
                Zf(FFT)(xtoken_fpr, logn_xtoken);
                Zf(poly_mul_fft)(xtoken_fpr, yid_fpr, logn_xtoken);
                // xtg_temp = floor(int32_t(xtoken_fpr) * P_l/q_l);
                xtg_temp = floor(int32_t(xtoken_fpr)); // * P_l/q_l);
                ::memcpy(xtg_local,  &xtg_temp, 32);
                // ::memcpy(xtg_local, (unsigned char*) xtoken_fpr, 32);
            
                // cout << DB_HexToStr_N(xtg_local,32) << std::endl;

                xtoken_local += EVP_MAX_BLOCK_LENGTH;
                xtg_local += EVP_MAX_BLOCK_LENGTH;
        
            }
            yid_local += 32;
            xtoken_local = XToken;
            xtg_local = XTAG;
            // yid_local = YID;

            for(int i=0;i<NWords;++i){//Check this length

                ::memset(bhash,0x00,bhash_block_size);
                FPGA_BLOOM_HASH(xtg_local,bhash);

                for(int j=0;j<N_HASH;++j){
                    bf_n_indices[j][i] = BFIdxConv(bhash+(64*j),N_BF_BITS);
                    // bf_n_indices[j][i] = (bhash[64*j] & 0xFF) + ((bhash[64*j+1] & 0xFF) << 8) + ((bhash[64*j+2] & 0x01) << 16);
                }

                xtg_local +=32;
            }

            BloomFilter_Match_N(BF, bf_n_indices, NWords, &idx_in_set);

            if(idx_in_set){
                ::memcpy(ec_local,EC,32);
                ec_local +=EVP_MAX_BLOCK_LENGTH;
                ++nmatch;
            }

            tset_row_local +=48;


        }

    }
    yid_local = YID;
    
    cout << "Nmatch: " << nmatch << endl;

    // unsigned char KE[32];

    // ::memset(KE,0x00,32);


    // if(!PKCS5_PBKDF2_HMAC_SHA1(KS1, strlen(KS1),NULL,0,1000,32,KS))
    // {
    //     printf("Error in key generation\n");
    //     exit(1);
    // }
    // while(!RAND_bytes(iv_ks,sizeof(iv_ks)));

    // w_local = W;
   
    // ke = encrypt(Q1, sizeof(KE)/sizeof(KE[0]), aad, sizeof(aad), KS, iv_ke, KE, tag_ks);
    // w_local = W;
   


    // const char* KE1 = reinterpret_cast<const char *> (KE);
    // if(!PKCS5_PBKDF2_HMAC_SHA1(KE1, strlen(KE1),NULL,0,1000,32,KE))
    // {
    //     printf("Error in key generation\n");
    //     exit(1);
    // }
    // while(!RAND_bytes(iv_ec,sizeof(iv_ec)));


    // uidx_local = UIDX;
    // ec_local = EC;
    // for(int i=0;i<nmatch;++i){
    //     kw_dec = decrypt(ec_local, sizeof(ec_local)/sizeof(ec_local[i]), aad, sizeof(aad), tag_ec, KE, iv_ec, uidx_local);
    //     uidx_local += sym_block_size;
    //     ec_local += EVP_MAX_BLOCK_LENGTH;
    // }
    // ec_local = EC;
    // uidx_local = UIDX;

    // cout << "Nmatch: " << nmatch << endl;

    // unsigned char KE[16];

    // ::memset(KE,0x00,16);

    // AESENC(KE,Q1,KS);

    // for(int i=0;i<nmatch;++i){
    //     AESDEC(UIDX+(16*i),ESET+(16*i),KE);
    // }


    for(unsigned int i=0;i<N_HASH;++i){
        delete [] bf_n_indices[i];
    }
    delete [] bf_n_indices;

    delete [] stag;
    delete [] tset_row;
    delete [] WC;
    delete [] XTAG;
    delete [] bhash;
    delete [] EC;

    delete [] YID;

    return nmatch;



}   


int main()
{
    cout << "Starting program..." << endl;


    UIDX = new unsigned char[16*N_max_ids];
    ::memset(UIDX,0x00,16*N_max_ids);
    
    ////////////////////////////////////////////////////////////////////////////////////////////////////////
    
    // std::map<std::string, unsigned int> kw_frequency;
    // std::vector<std::string> keyword_vec;
    std::vector<std::string> query;

    unsigned int n_keywords = 0;
    unsigned int n_iterations = 1;//Number of text vectors to search

    //----------------------------------------------------------------------------------------------
    // std::string kw_freq_file = "db_kw_freq.csv";
    // std::string res_query_file = "./results/res_query.csv";
    std::string res_id_file = "./results/res_id.csv";
    // std::string res_time_file = "./results/res_time.csv";

    // std::ifstream kw_freq_file_handle(kw_freq_file);

    // std::ofstream res_query_file_handle(res_query_file);
    std::ofstream res_id_file_handle(res_id_file);
    // std::ofstream res_time_file_handle(res_time_file);

    //----------------------------------------------------------------------------------------------
    std::vector<std::string> raw_row_data;
    // std::string widxdb_row;

    // std::stringstream ss;
    // std::string kw;
    // std::string kw_freq_str;

    //----------------------------------------------------------------------------------------------

    // kw_freq_file_handle.open(kw_freq_file,std::ios_base::in);
    // widxdb_row.clear();
    // raw_row_data.clear();

    // while(getline(kw_freq_file_handle,widxdb_row)){
    //     raw_row_data.push_back(widxdb_row);
    //     widxdb_row.clear();
    //     n_keywords++;
    // }

    // kw_freq_file_handle.close();

    // for(auto v: raw_row_data){
    //     ss.clear();
    //     ss << v;
        
    //     kw.clear();
    //     kw_freq_str.clear();

    //     std::getline(ss,kw,',');
    //     std::getline(ss,kw_freq_str,',');
        
    //     kw_frequency[kw] = std::stoi(kw_freq_str);
    //     keyword_vec.push_back(kw);
    // }

    //----------------------------------------------------------------------------------------------

    srand(time(NULL));

    //----------------------------------------------------------------------------------------------
    //Initialise
    Sys_Init();
    
    std::cout << "Reading Bloom Filter from disk..." << std::endl;
    BloomFilter_ReadBFfromFile(bloomfilter_file, BF); //Load bloom filter from file
    //----------------------------------------------------------------------------------------------
    // Search
    // for(int i=0;i<8;i++)
    // {
    //     std::cout << DB_HexToStr(BF[i]) << std::endl;
    // }
    
    auto search_start_time = std::chrono::high_resolution_clock::now();
    auto search_stop_time = std::chrono::high_resolution_clock::now();
    auto search_time_elapsed = std::chrono::duration_cast<std::chrono::microseconds>(search_stop_time - search_start_time).count();

    unsigned int kw_idx = 0;
    unsigned int kw_freq = 0;
    unsigned int n_q_kw = 2;//Number of keywords in a query to search for

    std::vector<unsigned int> idx_vec;
    std::map<unsigned int,unsigned int> freq_map;
    std::vector<unsigned int> idx_sorted;
    std::vector<unsigned int> freq_sorted;
    std::vector<std::string> kw_sorted;

    unsigned int nm = 0;
    unsigned char row_vec[2048]; //16 bytes * Number of keywords in the query
    int n_vec = 0;
    std::set<std::string> result_temp;

    for(unsigned int q_idx=0;q_idx<n_iterations;++q_idx)
    {
        query.clear();
        // freq_map.clear();

        // for(unsigned int i=0;i<n_q_kw;++i){
        //     kw_idx = rand() % n_keywords;
        //     kw_freq = kw_frequency[keyword_vec[kw_idx]];
        //     freq_map[kw_freq] = kw_idx;
        //     cout << "kw_idx = " << kw_idx << std::endl;
        //     cout << "kw_freq = " << kw_freq << std::endl;
        //     cout << "freq_map[kw_freq] = " << freq_map[kw_freq] << std::endl;

        // }

        // for(auto v:freq_map){
        //     query.push_back(keyword_vec[v.second]);
        // }

       
        // cout << "query = ";

        //  for(auto v:query){
        //     std::cout << v << std::endl;
        // }

        // if(query.size() < n_q_kw) continue;


        query.push_back("00000000");
        query.push_back("00000001");

        std::cout << "--------------------------------------------------" << std::endl;
        std::cout << "Searching for  ";
        
        for(auto v:query){
            std::cout << v << " ";
        }

        // std::cout << " with frequency ";
        // for(auto v:query){
        //     std::cout << kw_frequency[v] << " ";
        // }

        ::memset(row_vec,0x00,2048);
        n_vec = 0;

        for(auto rs:query){
            StrToHexBVec(row_vec+(16*n_vec),rs.data());//Defined in mainwindow.cpp file
            n_vec++;
        } 

        std::cout << n_vec << std::endl;
        
        ::memset(UIDX,0x00,16*N_max_ids);
        result_temp.clear();

        

        //-------------------------------------------------------------------------------
        search_start_time = std::chrono::high_resolution_clock::now();

        nm = EDB_Search(row_vec,(n_vec-1));

        search_stop_time = std::chrono::high_resolution_clock::now();
        search_time_elapsed = std::chrono::duration_cast<std::chrono::microseconds>(search_stop_time - search_start_time).count();

        std::cout << "Search time = " << search_time_elapsed << std::endl;

        for(unsigned int k=0;k<nm;++k){
            result_temp.insert(DB_HexToStr_N(UIDX+(16*k),16));
        }
        //-----------------------------------------------------------------------------

        for(auto v:result_temp){
            res_id_file_handle << v.substr(0,8) << ",";
        }
        res_id_file_handle << std::endl;

        // for(auto v:query){
        //     res_query_file_handle << v << ",";
        // }

        // for(auto v:query){
        //     res_query_file_handle << kw_frequency[v] << ",";
        // }

        // res_query_file_handle << result_temp.size() << "," << std::endl;
        // res_time_file_handle << search_time_elapsed << "," << std::endl;

        result_temp.clear();
        query.clear();
    }

    // res_query_file_handle.close();
    res_id_file_handle.close();
    // res_time_file_handle.close();

    //----------------------------------------------------------------------------------------------
    // Thread Release
    Sys_Clear();
    delete [] UIDX;
    //---------------------------------------------------------------------------------------------

    cout << "Program finished!" << endl;


    return 0;
}
