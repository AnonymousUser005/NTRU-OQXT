#include "mongodb_util.h"

mongocxx::instance instance{};
mongocxx::uri uri("mongodb://localhost:27017");
mongocxx::client client(uri);

mongocxx::database db = client["enronoxt"];
mongocxx::collection coll = db["TIDXDB"];

// Hex to string converter function (where n is the no. of bytes)
std::string MDB_HexToStr(unsigned char* hexarr, unsigned int n)
{
    std::stringstream ss;
    ss << std::hex;

    for (unsigned int i = 0; i < n; ++i){
        ss << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(hexarr[i]);
    }
    return ss.str();
}

int MDB_StrToHex(unsigned char* hexarr, std::string outstr)
{
    char temp[2];
    auto chrs = outstr.c_str();
    unsigned char *text = reinterpret_cast<unsigned char*>(const_cast<char*>(chrs));
    for (int i=0; i<49; i++){
        temp[0] = text[2*i];
        temp[1] = text[2*i+1];
        hexarr[i] = ::strtoul(temp,NULL,16) & 0xFF;
    }
    return 0;
}

int MDB_TIDXDB_Query(unsigned char* result, unsigned char* BIDX, unsigned char* JIDX, unsigned char* LBL)
{
    ::memset(result,0x00,49);
    bsoncxx::stdx::optional<bsoncxx::document::value> maybe_result = coll.find_one(document{}
        << "BIDX" << MDB_HexToStr(BIDX,2)
        << "JIDX" << MDB_HexToStr(JIDX,2)
        << "LBL" << MDB_HexToStr(LBL,12)
        << finalize
    );

    if(maybe_result){
        auto doc = maybe_result->view();
        bsoncxx::document::element doc_ele{doc["VAL"]};
        MDB_StrToHex(result, doc_ele.get_utf8().value.to_string());
    }
    return 0;
}

int MDB_TIDXDB_Query_N(unsigned char* result, mongocxx::collection &db_collection, unsigned char* BIDX, unsigned char* JIDX, unsigned char* LBL)
{
    ::memset(result,0x00,49);
    bsoncxx::stdx::optional<bsoncxx::document::value> maybe_result = db_collection.find_one(document{}
        << "BIDX" << MDB_HexToStr(BIDX,2)
        << "JIDX" << MDB_HexToStr(JIDX,2)
        << "LBL" << MDB_HexToStr(LBL,12)
        << finalize
    );

    if(maybe_result){
        auto doc = maybe_result->view();
        bsoncxx::document::element doc_ele{doc["VAL"]};
        MDB_StrToHex(result, doc_ele.get_utf8().value.to_string());
    }
    return 0;
}

int MDB_TIDXDB_Insert(unsigned char BIDX[2], unsigned char JIDX[2], unsigned char LBL[12], unsigned char VAL[49])
{
    coll.insert_one(bsoncxx::builder::stream::document{}
        << "BIDX" << MDB_HexToStr(BIDX,2)
        << "JIDX" << MDB_HexToStr(JIDX,2)
        << "LBL" << MDB_HexToStr(LBL,12)
        << "VAL" << MDB_HexToStr(VAL,49)
        << finalize
    );
    return 0;
}
