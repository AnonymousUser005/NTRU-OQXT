#include <cstdint>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <vector>

#include <mongocxx/instance.hpp>
#include <mongocxx/uri.hpp>
#include <mongocxx/client.hpp>
#include <mongocxx/pool.hpp>

#include <bsoncxx/json.hpp>
#include <bsoncxx/types.hpp>
#include <bsoncxx/builder/basic/kvp.hpp>
#include <bsoncxx/builder/stream/document.hpp>

using bsoncxx::builder::stream::document;
using bsoncxx::builder::stream::finalize;

std::string MDB_HexToStr(unsigned char *hexarr, unsigned int n);
int MDB_StrToHex(unsigned char* hexarr, std::string outstr);
int MDB_TIDXDB_Query(unsigned char* result, unsigned char* BIDX, unsigned char* JIDX, unsigned char* LBL);
int MDB_TIDXDB_Query_N(unsigned char* result, mongocxx::collection &db_collection, unsigned char* BIDX, unsigned char* JIDX, unsigned char* LBL);
int MDB_TIDXDB_Insert(unsigned char BIDX[2], unsigned char JIDX[2], unsigned char LBL[12],unsigned char VAL[49]);
