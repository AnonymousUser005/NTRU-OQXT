#include "oqxt-falcon_setup.h"


// string rawdb_file = "widxdb_small2.csv";
string rawdb_file = "db6k.dat";
string eidxdb_file = "eidxdb_small2.csv";
string bloomfilter_file = "bloom_filter.dat";//Bloom filter file


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
unsigned char iv_ks[16], iv_ki[16], iv_r[16], iv_ec[16], iv_ke[16];// iv_kz[16], iv_kx[16], iv_stag[16];
unsigned char tag_r[100], tag_ec[100], tag_kz[100], tag_ks[100], tag_ki[100], tag_kx[100], tag_kt[100],tag_stag[100]; 
unsigned char aad[16]="00000002";
int ke, kw, ka, kec, kt, k_stag, k_stag_query, k_stag_TSetRetrieve;
int kw_dec;
vector<int> kid_enc_vec, kid_dec_vec, kr_enc_vec;

unsigned char iv_kt[16] = {0x56,0x37,0xca,0x94,0xd5,0xe0,0xad,0x62,0x73,0x7c,0xba,0x48,0x8d,0x2d,0x4d,0xde};
unsigned char iv_stag[16] = {0x56,0x37,0xca,0x94,0xd5,0xe0,0xad,0x62,0x73,0x7c,0xba,0x48,0x8d,0x2d,0x4d,0xde};
unsigned char iv_kx[16] = {0x56,0x37,0xca,0x94,0xd5,0xe0,0xad,0x62,0x73,0x7c,0xba,0x48,0x8d,0x2d,0x4d,0xde};
unsigned char iv_kz[16] = {0x56,0x37,0xca,0x94,0xd5,0xe0,0xad,0x62,0x73,0x7c,0xba,0x48,0x8d,0x2d,0x4d,0xde};


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

sw::redis::ConnectionOptions connection_options;
sw::redis::ConnectionPoolOptions pool_options;

// // ---------------------------------------------------------------------------------------------------------------------------------- // //



int Sys_Init()
{
    
    // auto redis = Redis("tcp://default:password@127.0.0.1:6379/0");
    // std::cout << redis.ping() << std::endl;
    connection_options.host = "127.0.0.1";  // Required.
    BloomFilter_Init(BF);

    return 0;
}

int Sys_Clear()
{
    BloomFilter_Clean(BF);

    return 0;
}

void transpose(int A[][m_l], int B[][N_l])
{
    int i, j;
    for (i = 0; i < m_l; i++)
        for (j = 0; j < N_l; j++)
            B[i][j] = A[j][i];
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
    ::memcpy(GL_HASH_MSG,msg,EVP_MAX_BLOCK_LENGTH);

  
    SHA3_HASH(&hasher,GL_HASH_MSG,GL_HASH_DGST);

    ::memcpy(digest,GL_HASH_DGST,hash_block_size);

    return 0;
}

int MGDB_QUERY(unsigned char *RES, unsigned char *BIDX, unsigned char *JIDX, unsigned char *LBL)
{


    auto redis = Redis("tcp://127.0.0.1:6379");

    ::memcpy(GL_MGDB_BIDX,BIDX,(2));
    ::memcpy(GL_MGDB_JIDX,JIDX,(2));
    ::memcpy(GL_MGDB_LBL,LBL,(12));
    ::memset(GL_MGDB_RES,0x00,(49));
        
        
    string s = HexToStr(MGDB_BIDX,2) + HexToStr(MGDB_JIDX,2) + HexToStr(MGDB_LBL,12);
    auto val = redis.get(s);
    unsigned char *t_res = reinterpret_cast<unsigned char *>(val->data());
    DB_StrToHex49(MGDB_RES,t_res);

    // ::memcpy(RES,GL_MGDB_RES,(N_threads*49));
    ::memcpy(RES,GL_MGDB_RES,(49));

    return 0;
}




int TSet_SetUp()
{
    unsigned char *W;
    unsigned char *TW;
    unsigned char *stag;
    unsigned char *stagi;
    unsigned char *stago;
    unsigned char *hashin;
    unsigned char *hashout;
    
    int N_words = 0;
    unsigned int N_max_id_words = 0;
    
    N_words = (N_max_ids/N_threads) + ((N_max_ids%N_threads==0)?0:1);
    N_max_id_words = N_words * N_threads;

    auto redis = Redis("tcp://127.0.0.1:6379");
  

    TW = new unsigned char[48*N_max_id_words];
    W = new unsigned char[16*N_max_id_words];
    stag = new unsigned char[32*N_max_id_words];
    stagi = new unsigned char[32*N_max_id_words];
    stago = new unsigned char[32*N_max_id_words];
    hashin = new unsigned char[32*N_max_id_words];
    hashout = new unsigned char[64*N_max_id_words];

    //To store TSet Value -- single execution
    unsigned char TVAL[49*N_max_id_words];
    unsigned char TBIDX[2*N_max_id_words];
    unsigned char TJIDX[2*N_max_id_words];
    unsigned char TLBL[12*N_max_id_words];

    unsigned int *FreeB;
    int bidx=0;
    int len_freeb = 65536;
    int total_count = 0;
    int freeb_idx = 0;


    FreeB = new unsigned int[len_freeb];

    ifstream eidxdb_file_handle;
    eidxdb_file_handle.open(eidxdb_file,ios_base::in|ios_base::binary);

    stringstream ss;

    string eidxdb_row;
    vector<string> eidxdb_data;
    string eidxdb_row_current;
    string s;

    ::memset(hashin,0x00,32*N_max_id_words);
    ::memset(hashout,0x00,64*N_max_id_words);
    ::memset(TJIDX,0x00,2*N_max_id_words);

    for(int bc=0;bc<len_freeb;++bc){
        FreeB[bc] = 0;
    }

    int n_rows = 0;
    int n_row_ids = 0;

    eidxdb_row.clear();
    while(getline(eidxdb_file_handle,eidxdb_row)){
        eidxdb_data.push_back(eidxdb_row);
        eidxdb_row.clear();
        n_rows++;
    }

    eidxdb_file_handle.close();

    int current_row_len = 0;

    unsigned char *tw_local = TW;
    unsigned char *w_local = W;
    unsigned char *stag_local = stag;
    unsigned char *stagi_local = stagi;
    unsigned char *hashin_local = hashin;
    unsigned char *hashout_local = hashout;
    
    unsigned long id_count = 0;

    std::string db_in_key = "";
    std::string db_in_val = "";

    for(int n=0;n<n_rows;++n){

        ::memset(W,0x00,16*N_max_id_words);
        ::memset(TW,0x00,48*N_max_id_words);
        ::memset(stag,0x00,32*N_max_id_words);
        ::memset(stagi,0x00,32*N_max_id_words);
        ::memset(stago,0x00,32*N_max_id_words);
        ::memset(hashin,0x00,32*N_max_id_words);
        ::memset(hashout,0x00,64*N_max_id_words);

        eidxdb_row_current = eidxdb_data.at(n);

        ss.str(std::string());
        ss << eidxdb_row_current;

        std::getline(ss,s,',');//Get the keyword
        DB_StrToHex8(W,s.data());//Read the keyword
        // std::cout << DB_HexToStr(W) << std::endl;

        tw_local = TW;
        n_row_ids = 0;
        while(std::getline(ss,s,',') && !ss.eof()) {
            if(!s.empty()){
                DB_StrToHex48(tw_local,s.data());//Read the id
                // std::cout << DB_HexToStr_N(tw_local,48) << std::endl;
                tw_local += 48;
                n_row_ids++;
            }
        }
        // std::cout << std::endl;

        ss.clear();
        ss.seekg(0);

        tw_local = TW;

        N_words = (n_row_ids/N_threads) + ((n_row_ids%N_threads==0)?0:1);


        stag_local = stag;
        w_local = W;
        kt = encrypt(w_local, sizeof(stag_local)/sizeof(*stag_local), aad, sizeof(aad), KT, iv_kt, stag_local, tag_kt);
        stag_local += EVP_MAX_BLOCK_LENGTH;
        w_local += 16;
      
        stag_local = stag;
        w_local = W;
        
        // cout << DB_HexToStr_N(stag,32) << endl;

        //Fill stagi array
        stagi_local = stagi;
        for(int nword = 0;nword < N_words;++nword){
            for(int nid=0;nid<N_threads;nid++){
                // stagi_local[0] >>= 16;
                stagi_local[0] = ((nword*N_threads)+nid) & 0xFF; 
                stagi_local += EVP_MAX_BLOCK_LENGTH;
            }
        }
        stagi_local = stagi;

     
        //PRF of stag and i
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
            k_stag = encrypt(stagi_local, sizeof(hashin_local)/sizeof(hashin_local[n]), aad, sizeof(aad), stag, iv_stag, hashin_local, tag_stag);
            // FPGA_AES_ENC(stagi_local,stag,hashin_local);
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
            // std::cout << DB_HexToStr_N(hashout_local,64) << endl;
            hashin_local += EVP_MAX_BLOCK_LENGTH;
            hashout_local += hash_block_size;
        }
        hashin_local = hashin;
        hashout_local = hashout;

        // std::cout << std::endl;


        //Should be done for each stag
        for(int bc=0;bc<len_freeb;++bc){
            FreeB[bc] = 0;
        }

        tw_local = TW;
        

        for(int i=0;i<n_row_ids;++i){
            ::memcpy(TVAL+1,tw_local,48);
           

            TVAL[0] = (i==(n_row_ids-1))?0x01:0x00;
            for(int j=0;j<49;++j){
                TVAL[j] = hashout[64*i+15+j] ^ TVAL[j];
            }
        
            
            ::memcpy(TBIDX,(hashout+(64*i)),2);
            ::memcpy(TLBL,(hashout+(64*i)+2),12);

            freeb_idx = (TBIDX[1] << 8) + TBIDX[0];

            bidx = (FreeB[freeb_idx]++);
            TJIDX[0] =  bidx & 0xFF;
            TJIDX[1] =  (bidx >> 8) & 0xFF;

            // MDB_TIDXDB_Insert(TBIDX, TJIDX, TLBL,TVAL);
            db_in_key.clear();
            db_in_val.clear();
            db_in_key = HexToStr(TBIDX,2) + HexToStr(TJIDX,2) + HexToStr(TLBL,12);
            // std::cout << "s = " << db_in_key <<std::endl;
            // std::cout << HexToStr(TBIDX,2) << ", " << HexToStr(TJIDX,2) << ", " << HexToStr(TLBL,12) << std::endl;
            db_in_val = HexToStr(TVAL,49);
            redis.set(db_in_key.data(), db_in_val.data());

            tw_local += 48;
            total_count++;
        }
        // std::cout << "\nNext Keyword ..." << std::endl;
    }
 
    std::cout << "Total ID Count: " << total_count << std::endl;

    delete [] TW;
    delete [] W;
    delete [] stag;
    delete [] stagi;
    delete [] stago;
    delete [] hashin;
    delete [] hashout;

    delete [] FreeB;

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


int main()   
{
    unsigned char *W;
    unsigned char *ID;
    unsigned char *KE;
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
    uint8_t *YID;
    unsigned char *XW;         
    unsigned char *XID;
    unsigned char *XW_poly;         
    unsigned char *XID_poly;
    unsigned char *XTAG;    
    
   

    W = new unsigned char[16];                                 //Holds the keyword
    ID = new unsigned char[16*N_max_id_words];                 //Maximum number of IDs in a row
    WC = new unsigned char[16*N_max_id_words];                 //IDs with counter value(for computing randomness R)
    KE = new unsigned char[EVP_MAX_BLOCK_LENGTH];                           //ID encryption key
    R = new unsigned char[N_max_id_words*EVP_MAX_BLOCK_LENGTH];          //Random value for generating trapdoor matrix -- used in generating A
    EC = new unsigned char[EVP_MAX_BLOCK_LENGTH*N_max_id_words];                           //Encrypted IDs
    Yid = new unsigned char[16*N_l*m_l];
    XWE = new unsigned char[N_max_id_words*EVP_MAX_BLOCK_LENGTH];        
    dec_pt = new unsigned char[N_max_id_words*EVP_MAX_BLOCK_LENGTH];        
    XIDE = new unsigned char[N_max_id_words*EVP_MAX_BLOCK_LENGTH];       //Encrypt IDs using AES-256
    dec_pt_id = new unsigned char[N_max_id_words*EVP_MAX_BLOCK_LENGTH];        
    XW = new unsigned char [N_max_id_words*EVP_MAX_BLOCK_LENGTH];    //XW for LWR sample generation
    XID = new unsigned char [N_max_id_words*EVP_MAX_BLOCK_LENGTH]; 
    XTAG = new unsigned char [N_max_id_words*EVP_MAX_BLOCK_LENGTH];
    T = new int[16*m_l*N_max_id_words];                         //secret key of Falcon for signature generation
    ZW = new int[16*m_l*N_max_id_words];                        //public-key for verification of signature
    YID = new uint8_t [32*N_max_id_words];
    bhash = new unsigned char[64*N_HASH];
    XW_poly = new unsigned char [N_max_id_words*EVP_MAX_BLOCK_LENGTH];    
    XID_poly = new unsigned char [N_max_id_words*EVP_MAX_BLOCK_LENGTH]; 

    ifstream rawdb_file_handle;
    rawdb_file_handle.open(rawdb_file,ios_base::in|ios_base::binary);

    ofstream eidxdb_file_handle;
    eidxdb_file_handle.open(eidxdb_file,ios_base::out|ios_base::binary);

    stringstream ss;

    string rawdb_row;
    vector<string> rawdb_data;
    string rawdb_row_current;
    string s;

    unsigned int bfidx = 0;
    unsigned int bf_indices[N_HASH];


    ::memset(W,0x00,16);
    ::memset(ID,0x00,16*N_max_id_words);
    ::memset(WC,0x00,16*N_max_id_words);
    ::memset(KE,0x00,EVP_MAX_BLOCK_LENGTH);
    ::memset(R,0x00,N_max_id_words*EVP_MAX_BLOCK_LENGTH);
    ::memset(EC,0x00,N_max_id_words*EVP_MAX_BLOCK_LENGTH);
    ::memset(XWE,0x00,N_max_id_words*EVP_MAX_BLOCK_LENGTH);
    ::memset(dec_pt,0x00,N_max_id_words*EVP_MAX_BLOCK_LENGTH);
    ::memset(XIDE,0x00,N_max_id_words*EVP_MAX_BLOCK_LENGTH);
    ::memset(dec_pt_id,0x00,N_max_id_words*EVP_MAX_BLOCK_LENGTH);
    ::memset(Yid, 0x00, 16*N_l*m_l);
    ::memset(XW,0x00, N_max_id_words*EVP_MAX_BLOCK_LENGTH);
    ::memset(XID,0x00, N_max_id_words*EVP_MAX_BLOCK_LENGTH);
    ::memset(XTAG,0x00, N_max_id_words*EVP_MAX_BLOCK_LENGTH);
    ::memset(T,0x00,16*m_l*N_max_id_words);
    ::memset(ZW,0x00,16*m_l*N_max_id_words);
    ::memset(YID,0x00,32*N_max_id_words);
    ::memset(bhash,0x00,64*N_HASH);
    ::memset(XW_poly,0x00, N_max_id_words*EVP_MAX_BLOCK_LENGTH);
    ::memset(XID_poly,0x00,N_max_id_words*EVP_MAX_BLOCK_LENGTH);



    
    unsigned char *id_local = ID;
    unsigned char *ke_local = KE;
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
    unsigned char *xtag_local = XTAG;
    int *t_local = T;
    int *zw_local = ZW;
    uint8_t *yid_local = YID;



    unsigned char *local_s;

    int n_rows = 0;
    int n_row_ids = 0;

    Sys_Init();

    rawdb_row.clear();
    while(getline(rawdb_file_handle,rawdb_row)){
        rawdb_data.push_back(rawdb_row);
        rawdb_row.clear();
        n_rows++;
    }

    cout << "Number of Keywords: " << n_rows << endl;

    rawdb_file_handle.close();

    auto start_time = std::chrono::high_resolution_clock::now();
    int count = 0;
    for(unsigned int n1=0; n1<n_rows; ++n1) // for every keyword
    {
        wc_local = WC;
        w_local = W;
        r_local = R;
        ke_local = KE;
        

        ::memset(ID,0x00,16*N_max_id_words);
        ::memset(KE,0x00,32*EVP_MAX_BLOCK_LENGTH);
        ::memset(R,0x00,N_max_id_words*EVP_MAX_BLOCK_LENGTH);
        ::memset(EC,0x00,N_max_id_words*EVP_MAX_BLOCK_LENGTH);
        ::memset(XWE,0x00,N_max_id_words*EVP_MAX_BLOCK_LENGTH);
        ::memset(dec_pt,0x00,N_max_id_words*EVP_MAX_BLOCK_LENGTH);
        ::memset(XIDE,0x00,N_max_id_words*EVP_MAX_BLOCK_LENGTH);
        ::memset(dec_pt_id,0x00,N_max_id_words*EVP_MAX_BLOCK_LENGTH);
        ::memset(XW,0x00, N_max_id_words*EVP_MAX_BLOCK_LENGTH);
        ::memset(XID,0x00, N_max_id_words*EVP_MAX_BLOCK_LENGTH);
        ::memset(XTAG,0x00, N_max_id_words*EVP_MAX_BLOCK_LENGTH);
        ::memset(T,0x00, 16*N_max_id_words);
        ::memset(ZW,0x00, 16*N_max_id_words);
        ::memset(YID, 0x00, 32*N_max_id_words);


        rawdb_row_current = rawdb_data.at(n1);

        ss.str(std::string());
        ss << rawdb_row_current;
        std::getline(ss,s,',');             // Read inverted index row

        
        DB_StrToHex8(W,s.data());           //Read the keyword        
        id_local = ID;

        n_row_ids = 0;                                  //For row id count
        while(std::getline(ss,s,',') && !ss.eof()) {
            if(!s.empty()){
                DB_StrToHex8(id_local,s.data());        //Read the id
                
                id_local += 16;
                n_row_ids++;
            }
        }

        count += n_row_ids;         //To get the total number of IDs in the DB
        ss.clear();
        ss.seekg(0);


        id_local = ID;              //Set local id pointer to the beginning of the array


       
        //Generate KE from W and KS
        if(!PKCS5_PBKDF2_HMAC_SHA1(KS1, strlen(KS1),NULL,0,1000,32,KS))
        {
            printf("Error in key generation\n");
            exit(1);
        }
        while(!RAND_bytes(iv_ks,sizeof(iv_ks)));

        w_local = W;
        ke_local = KE;
        ke = encrypt(w_local, sizeof(ke_local)/sizeof(ke_local[n1]), aad, sizeof(aad), KS, iv_ke, ke_local, tag_ks);
        w_local = W;
        ke_local = KE;


        //Generate XW (PRF output of KX and W)
        // if(!PKCS5_PBKDF2_HMAC_SHA1(KX1, strlen(KX1),NULL,0,1000,32,KX))
        // {
        //     printf("Error in key generation\n");
        //     exit(1);
        // }
        // while(!RAND_bytes(iv_kx,sizeof(iv_kx)));

        xwe_local = XWE;
        xw_local = XW;
        w_local = W;
        kw = encrypt(w_local, sizeof(xw_local)/sizeof(xw_local[n1]), aad, sizeof(aad), KX, iv_kx, xw_local, tag_kx);
        xw_local = XW;
        w_local = W;

        // cout << DB_HexToStr_N(xw_local,32) << " ----- " << std::endl;

        //Decrypting encrypted keywords --> XWE
        // xw_local = XW;
        // dec_pt_local = dec_pt;
        // kw_dec = decrypt(xw_local, kw, aad, sizeof(aad), tag_kx, KX, iv_kx, dec_pt_local);
        // xw_local = XW;
        // dec_pt_local = dec_pt;
        
        
        //Printing to test encryption-decryption process
        // cout << "\n" << DB_HexToStr(w_local) << "\t --> ";
        // cout << DB_HexToStr(xw_local) << "\n ";



        //Generate random polynomial wrt XW from Falcon specifications
        inner_shake256_context sc_xw;
        // tlen = 40960;   for mk_rand_poly() used in test_falcon
        size_t tlen_xw = 90112;
        int8_t *f_xw = xmalloc(tlen_xw);
        // size_t n_xw = (size_t)1 << logn_xw;
        // uint16_t *hm_xw  = (uint16_t *) (f_xw +6*n_xw);
        int8_t logn_xw = 4;
        fpr *xw_fpr = (fpr*) f_xw;
        prng p;

        inner_shake256_init(&sc_xw); 		                            //Initialises the array A to all 0
		inner_shake256_inject(&sc_xw, (const uint8_t*) xw_local, sizeof xw_local);	// injects msg to context sc
		inner_shake256_flip(&sc_xw);

		Zf(prng_init)(&p, &sc_xw);                                  
        mk_rand_poly_oqxt(&p, xw_fpr, logn_xw);     

        
        id_local = ID;
        xid_local = XID;
        xtag_local = XTAG;
        for(unsigned int nword=0; nword<n_row_ids; nword++)
        {

            //Generate XIDE
            if(!PKCS5_PBKDF2_HMAC_SHA1(KI1, strlen(KI1),NULL,0,1000,32,KI))
            {
                std::cout << "Error in key generation\n" << std::endl;
                exit(1);
            }
            while(!RAND_bytes(iv_ki,sizeof(iv_ki)));

        
        // id_local = ID;
        // xid_local = XID;
        // for(unsigned int nword=0; nword<n_row_ids; nword++)
        // {
            // unsigned char array[16];
            int kid = encrypt(id_local, sizeof(xid_local)/sizeof(xid_local[nword]), aad, sizeof(aad), KI, iv_ki, xid_local, tag_ki);        
            kid_enc_vec.push_back(kid);
            // std::copy(xid_local,xid_local+16,array);
            // cout << DB_HexToStr(id_local) << " -- " << DB_HexToStr_N(array,16) << std::endl;
            id_local += 16;
            xid_local += EVP_MAX_BLOCK_LENGTH;
            
        // }
        // id_local = ID;
        // xid_local = XID;
      

        //Printing to test encryption-decryption process
        // id_local = ID;
        // xid_local = XID;
        // for(unsigned int nword=0; nword<n_row_ids; nword++)
        // {
        //     cout << "\n" << DB_HexToStr(id_local) << "\t --> ";
        //     cout << DB_HexToStr(xid_local) << "\n ";
        //     id_local += sym_block_size;
        //     xid_local += EVP_MAX_BLOCK_LENGTH;
        // }
        // id_local = ID;
        // xid_local = XID;



        //Generate random polynomial wrt XID from Falcon specifications
        // xid_local = XID;
        // xtag_local = XTAG;
        // // int counter = 0;
        // for(unsigned int nword=0; nword<n_row_ids; nword++)
        // {
            unsigned char array_xid[8];
            double xtag_temp;
            inner_shake256_context sc_xid;
            size_t tlen_xid = 90112;
            int8_t *f_xid = xmalloc(tlen_xid);
            int8_t logn_xid = 4; //+ counter;
            fpr *xid_fpr = (fpr*) f_xid;
            prng p_xid;


            std::copy(xid_local,xid_local+8,array_xid);
            inner_shake256_init(&sc_xid); 		                            //Initialises the array A to all 0
            inner_shake256_inject(&sc_xid, array_xid, sizeof array_xid);	        // injects msg to context sc
            inner_shake256_flip(&sc_xid);

            // cout << sc_xid.st.A << " -- " << sc_xid.st.dbuf << std::endl;

            
            Zf(prng_init)(&p_xid, &sc_xid);                                  
            mk_rand_poly_oqxt(&p_xid, xid_fpr, logn_xid);                         



            Zf(FFT)(xid_fpr, logn_xid);
            Zf(FFT)(xw_fpr, logn_xw);
            Zf(poly_mul_fft)(xw_fpr, xid_fpr, logn_xw);
            xtag_temp = floor(int32_t(xw_fpr) * P_l/q_l);
            ::memcpy(xtag_local, &xtag_temp, 32);
           

            // cout << DB_HexToStr_N(xtag_local,32) << std::endl;
           
            xid_local += EVP_MAX_BLOCK_LENGTH;
            xtag_local += EVP_MAX_BLOCK_LENGTH;
            // counter += 1;

        }
        xid_local = XID;
        xtag_local = XTAG;
        // cout << DB_HexToStr_N(XTAG,32) << std::endl;
        // std::cout << std::endl;

        
        //Generating Public key, Private Key and Signature

        /* Computing randomness r to pass to keygen algorithm */

            // (append w || counter)
            wc_local = WC;
            for(int nword=0; nword<n_row_ids; ++nword)
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


            unsigned int count_wc = 1;
            unsigned int count_wc_local = 0;
            r_local = R;
            wc_local = WC;
            unsigned char pt[16];
            for(unsigned int nword=0; nword<n_row_ids; nword++)
            {
                count_wc_local = count_wc;
                *(wc_local+0) = count_wc_local & 0xFF;
                count_wc_local >>= 8;
                *(wc_local+1) = count_wc_local & 0xFF;
                count_wc++;

                // cout << DB_HexToStr_N(wc_local,16) << std::endl;
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
        xid_local = XID;
        yid_local = YID;
        r_local = R;
        for(unsigned int nword=0; nword<n_row_ids; nword++)
        {
            /* Key Generation */
            unsigned char array_r[8];
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

            std::copy(r_local,r_local+8,array_r);
            // cout << DB_HexToStr_N(r_local,8) << std::endl;
            inner_shake256_init(&sc_keygen);
            inner_shake256_inject(&sc_keygen, array_r, sizeof array_r);
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
    

            /* Signature Generation */

            //Public key h in NTT-Montgomery Form
            ::memcpy(h_mont, h, n_keygen * sizeof *h_mont);
	        Zf(to_ntt_monty)(h_mont, logn_keygen);

            
            //Expanded private key for NTT operations
            expanded_key = (fpr *)tt_sign;
            tt_sign = (uint8_t *)expanded_key + (8 * logn_keygen + 40) * n_keygen;
            Zf(expand_privkey)(expanded_key, f, g, F, G, logn_keygen, tt_sign);
 

        
            //Hash of message (XID)
            unsigned char array_xid[8];
            inner_shake256_context sc_xid1;
            size_t tlen_xid1 = 90112;
            int8_t *f_xid1 = xmalloc(tlen_xid1);
            int8_t logn_xid1 = 4;
            size_t n_xid1 = (size_t)1 << logn_xid1;
            uint16_t *hm_xid1  = (uint16_t *) (f_xid1 +6*n_xid1);


            std::copy(xid_local,xid_local+8,array_xid);
            inner_shake256_init(&sc_xid1); 		                            //Initialises the array A to all 0
            inner_shake256_inject(&sc_xid1, array_xid, sizeof array_xid);	// injects msg to context sc
            inner_shake256_flip(&sc_xid1);
            Zf(hash_to_point_vartime)(&sc_xid1, hm_xid1, logn_xid1);

            
            // Signature Computation --
            //Compute a signature over the provided hashed message sc_xid; the signature value is one short vector.
            //On successful output, the start of the tt_sign buffer contains the s1 vector (int16_t elements).
            //The minimal size (in bytes) of tt_sign is 48*2^logn bytes. 
            Zf(sign_tree)(sig_keygen, &sc_xid1, expanded_key, hm_xid1, logn_keygen, tt_sign);

            ::memcpy(yid_local,tt_sign,32);

            // cout << yid_local << std::endl;

            yid_local += 32;
            xid_local += EVP_MAX_BLOCK_LENGTH;
            r_local += EVP_MAX_BLOCK_LENGTH;


            //Signature Verification
            if (!Zf(verify_raw)(hm_xid1, sig_keygen, h_mont, logn_keygen, tt_sign)){
                fprintf(stderr, "self signature (dyn) not verified\n");
                exit(EXIT_FAILURE);
		    }   

        
        }
        xid_local = XID;
        yid_local = YID;
        r_local = R;

        // std::cout << std::endl;


        
        //AES Encryption of id using KE
        const char* KE1 = reinterpret_cast<const char *> (KE);
        if(!PKCS5_PBKDF2_HMAC_SHA1(KE1, strlen(KE1),NULL,0,1000,32,KE))
        {
            printf("Error in key generation\n");
            exit(1);
        }
        while(!RAND_bytes(iv_ec,sizeof(iv_ec)));

        
        id_local = ID;
        ec_local = EC;
        for(unsigned int nword=0; nword<n_row_ids; nword++)
        {
            kec = encrypt(id_local, sizeof(ec_local)/sizeof(ec_local[nword]), aad, sizeof(aad), KE, iv_ec, ec_local, tag_ec);
            id_local += sym_block_size;
            ec_local += EVP_MAX_BLOCK_LENGTH;
        }
        id_local = ID;
        ec_local = EC;


        eidxdb_file_handle << DB_HexToStr8(W) << ",";            
        for(int n_eidx=0;n_eidx < n_row_ids;++n_eidx){
            eidxdb_file_handle << HexToStr(YID+(32*n_eidx),32) << HexToStr(EC+(32*n_eidx),16) + ",";
        }
        eidxdb_file_handle << endl;
        

      
        xtag_local = XTAG;
        for(int i=0;i<n_row_ids;++i)
        {

            ::memset(bhash,0x00,bhash_block_size);
            ::memset(bf_indices,0x00,N_HASH);


            // std::cout << DB_HexToStr(bhash) << std::endl; 
            FPGA_BLOOM_HASH(xtag_local,bhash);
        
            for(int j=0;j<N_HASH;++j){
                bf_indices[j] = BFIdxConv(bhash+(64*j),N_BF_BITS);
            }

            BloomFilter_Set(BF, bf_indices);

            xtag_local += EVP_MAX_BLOCK_LENGTH;
        }
        
        xtag_local = XTAG;

    }

    // eidxdb_file_handle.flush();
    eidxdb_file_handle.close();

    ///////////////////////////////////////////////////////////////////////////////////////////////
  
    cout << "TSet SetUp Starting!" << endl << endl;

    TSet_SetUp();

    
    cout << "TSet SetUp Done!" << endl;

    auto stop_time = chrono::high_resolution_clock::now();

    std::cout << "Writing Bloom Filter to disk..." << std::endl;
    BloomFilter_WriteBFtoFile(bloomfilter_file, BF); //Store bloom filter in file


    Sys_Clear();

    
    auto time_elapsed = chrono::duration_cast<chrono::microseconds>(stop_time - start_time).count();
    std::cout << "[*] Setup-time: " << time_elapsed << " micro-seconds" << endl;



    return 0;
}   

