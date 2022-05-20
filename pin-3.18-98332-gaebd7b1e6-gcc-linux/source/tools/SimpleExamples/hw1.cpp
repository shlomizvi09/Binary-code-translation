//
// Created by oweizman on 5/8/2022.
//
#include "pin.H"
#include <iostream>
#include <vector>
#include <map>
#include <fstream>
#include <algorithm>
#include <sstream>

using namespace std;
using std::cout;
using std::cerr;
using std::endl;

using std::fstream;
using std::map;
using std::vector;
using std::string;


/* ===================================================================== */
/* Global Variables */
/* ===================================================================== */

int cmp(pair<ADDRINT, UINT32> a, pair<ADDRINT, UINT32> b){
    return a.second > b.second;
}

// Data structures
map<ADDRINT, string> imgNametMap;      // image name map: key - routine address, value - image name
map<ADDRINT, ADDRINT> imgAddrMap; // image address map: key - routine address, value - image address
map<ADDRINT, string> rtnNameMap;       // routine name map: key - routine address, value - routine name
map<ADDRINT, UINT32> insCountMap;        // instruction count map: key - routine address, value - instruction count


/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */


/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    cerr <<
         "This tool prints out the number of dynamic instructions executed to stderr.\n"
         "\n";

    cerr << KNOB_BASE::StringKnobSummary();

    cerr << endl;

    return -1;
}

/* ===================================================================== */

VOID docount(ADDRINT rtn_addr)
{
    insCountMap[rtn_addr]++;
}

/* ===================================================================== */

VOID Instruction(INS ins, VOID *v)
{
    // get address of instruction
    ADDRINT addr = INS_Address(ins);

    // get routine by instruction address
    RTN rtn = RTN_FindByAddress(addr);
    if (rtn == RTN_Invalid())
        return;

    // get image by instruction address
    IMG img = IMG_FindByAddress (addr);
    if (img == IMG_Invalid())
        return;

    // get address of routine
    ADDRINT rtn_addr = RTN_Address(rtn);

    //update maps, key is routine address
    // check if routine is in the map. if not, insert a new pair with instruction counter = 0
    std::map<ADDRINT,UINT32>::iterator it = insCountMap.find(rtn_addr);
    if (it == insCountMap.end()) {
        insCountMap.insert(std::pair<ADDRINT, UINT32>(rtn_addr, 0));
        imgAddrMap.insert(std::pair<ADDRINT, ADDRINT>(rtn_addr,IMG_LowAddress(img)));
        imgNametMap.insert(std::pair<ADDRINT, string>(rtn_addr,IMG_Name(img)));
        rtnNameMap.insert(std::pair<ADDRINT, string>(rtn_addr,RTN_Name(rtn)));

    }
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount, IARG_ADDRINT, rtn_addr, IARG_END);
}

/* ===================================================================== */

VOID Fini(INT32 code, VOID *v)
{
    // Convert insCountMap into a vector
    vector< pair<ADDRINT, UINT32> > inst_count_vec(insCountMap.begin(), insCountMap.end());

    // Sort instruction counter vector by num of instructions
    sort(inst_count_vec.begin(), inst_count_vec.end(), cmp);

    // Write to csv file
    fstream fout;
    fout.open("rtn-output.csv", std::ios::out );
    for (const auto &it : inst_count_vec) {

        std::ostringstream ss1;
        ss1 << "0x" << std::hex << imgAddrMap[it.first];
        std::string image_addr_hex = ss1.str();
        std::ostringstream ss2;
        ss2 << "0x" << std::hex <<it.first;
        std::string rtn_addr_hex = ss2.str();

        // Write csv row
        fout << imgNametMap[it.first] << ", "
             << image_addr_hex<< ", "
             << rtnNameMap[it.first] << ", "
             << rtn_addr_hex<< ", "
             << it.second
             << "\n";
    }
    fout.close();
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char *argv[])
{
    if( PIN_Init(argc,argv) )
    {
        return Usage();
    }

    PIN_InitSymbols();
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);

    // Never returns
    PIN_StartProgram();

    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */


