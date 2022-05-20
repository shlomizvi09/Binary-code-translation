/*
 * Copyright 2002-2020 Intel Corporation.
 * 
 * This software is provided to you as Sample Source Code as defined in the accompanying
 * End User License Agreement for the Intel(R) Software Development Products ("Agreement")
 * section 1.L.
 * 
 * This software and the related documents are provided as is, with no express or implied
 * warranties, other than those that are expressly stated in the License.
 */

/*! @file
 *  This file contains an ISA-portable PIN tool for counting dynamic instructions
 */

#include "pin.H"
#include <iostream>

#include <vector>
#include <map>
#include <fstream>
#include <algorithm>    // std::sort
#include <sstream>


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

// Saves all data for each csv row
class entry {
public:
	string img_name;
	ADDRINT img_addr;   
	string rtn_name;
    ADDRINT rtn_addr;   
    UINT32 num_of_ins;
	
	entry(string img_name1, ADDRINT img_addr1, string rtn_name1, ADDRINT rtn_addr1, UINT32 num_of_ins1){
		img_name = img_name1;
		img_addr = img_addr1;
		rtn_name = rtn_name1;
		rtn_addr = rtn_addr1;
		num_of_ins = num_of_ins1;
	}
	
	bool operator < (const entry &rhs) const { 
		return (num_of_ins > rhs.num_of_ins); 	//for revese sort
	}
	
	bool operator == (const entry &rhs) const {
		return (num_of_ins == rhs.num_of_ins);
	}
	
};


vector<entry> routines; // voctor of all entries, used for sorting and writing each entry to csv
map<ADDRINT, UINT32> insCountMap; // instruction count map, RTN address as key 

int invalid_ins = 0;

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

VOID docount(ADDRINT  rtn_addr)
{
	insCountMap[rtn_addr]++;
}

/* ===================================================================== */

VOID Routine(RTN rtn, VOID *v)
{	
	// Get routine, routine address and routine name 
	RTN rtn = INS_Rtn (ins);
	if (rtn == RTN_Invalid()){
		invalid_ins ++ ;
		//cout<< "rtn invalid" << endl;
		return;
	}
	ADDRINT rtn_addr = RTN_Address (rtn);
	string rtn_name = RTN_Name(rtn);
	
	// Get image, image address and image name
	IMG img = IMG_FindByAddress (rtn_addr);
	if (img == IMG_Invalid()){
		//cout << "img invalid" << endl;
		return;
	}
	string img_name = IMG_Name(img);
	ADDRINT img_addr = IMG_LowAddress(img);
	

	std::map<ADDRINT,UINT32>::iterator it = insCountMap.find(rtn_addr); // Check if routine is already in map
	if (it == insCountMap.end()){ //new routine
		insCountMap.insert(std::pair<ADDRINT, UINT32>(rtn_addr,0));	// add the new routine with instruction count 0
		routines.push_back(entry(img_name, img_addr,rtn_name, rtn_addr, 0)); // Add new entry to routines vector when routine is new
	}
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount, IARG_ADDRINT, rtn_addr, IARG_END);
}

/* ===================================================================== */

VOID Fini(INT32 code, VOID *v)
{
	int count = 0;
	// Adding num of instructions to routines vector
	for (std::map<ADDRINT,UINT32>::iterator it = insCountMap.begin(); it!=insCountMap.end(); ++it){
		for (auto &iter : routines){
			if (iter.rtn_addr == it->first){
				iter.num_of_ins += it->second;
				count +=  it->second;
			}
		}
	}
	
	// Sorting by num_of_instructions
	std::sort(routines.begin(), routines.end());
	
	// Writing to csv file
	fstream fout;
    fout.open("rtn-output.csv", std::ios::out );
	//cout<<"size of routines: "<<routines.size()<<endl; 
	for (const auto &it : routines) { 
	
		// Convert addresses to right format
		std::ostringstream ss1;
		ss1 << "0x" << std::hex << it.img_addr;
		std::string img_addr_hex = ss1.str();
		std::ostringstream ss2;
		ss2 << "0x" << std::hex <<it.rtn_addr;
		std::string rtn_addr_hex = ss2.str();
		
		// Write csv row
		fout << it.img_name << ", "
		     << img_addr_hex<< ", "
			 << it.rtn_name << ", "
			 << rtn_addr_hex<< ", "
             << it.num_of_ins
             << "\n";
	}
	fout.close();
	//cout << "count" << count << endl;
	//cout << "invalid ins " << invalid_ins << endl;
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
    RTN_AddInstrumentFunction(Routine, 0);
    PIN_AddFiniFunction(Fini, 0);

    // Never returns
    PIN_StartProgram();
    
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
