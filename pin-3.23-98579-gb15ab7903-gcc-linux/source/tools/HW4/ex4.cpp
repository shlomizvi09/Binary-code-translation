/*########################################################################################################*/
// cd /nfs/iil/ptl/bt/ghaber1/pin/pin-2.10-45467-gcc.3.4.6-ia32_intel64-linux/source/tools/SimpleExamples
// make
//  ../../../pin -t obj-intel64/rtn-translation.so -- ~/workdir/tst
/*########################################################################################################*/
/*BEGIN_LEGAL 
Intel Open Source License 

Copyright (c) 2002-2011 Intel Corporation. All rights reserved.
 
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.  Redistributions
in binary form must reproduce the above copyright notice, this list of
conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.  Neither the name of
the Intel Corporation nor the names of its contributors may be used to
endorse or promote products derived from this software without
specific prior written permission.
 
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE INTEL OR
ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
END_LEGAL */
/* ===================================================================== */

/* ===================================================================== */
/*! @file
 * This probe pintool generates translated code of routines, places them in an allocated TC 
 * and patches the orginal code to jump to the translated routines.
 */

#include "pin.H"
extern "C" {
#include "xed-interface.h"
}
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <values.h>

#include <algorithm>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <vector>

using namespace std;

#define UNROLL_COUNT 4
#define START_ADDRESS 0x409fde
#define END_ADDRESS 0x40a076
#define CMP_ADDRESS 0x40a070
#define MOV_ADDRESS 0x40a06d
#define ADD_ADDRESS 0x40a069
#define INVALID 0

/*======================================================================*/
/* commandline switches                                                 */
/*======================================================================*/
KNOB<BOOL> KnobVerbose(KNOB_MODE_WRITEONCE, "pintool",
                       "verbose", "0", "Verbose run");

KNOB<BOOL> KnobDumpTranslatedCode(KNOB_MODE_WRITEONCE, "pintool",
                                  "dump_tc", "0", "Dump Translated Code");

KNOB<BOOL> KnobDoNotCommitTranslatedCode(KNOB_MODE_WRITEONCE, "pintool",
                                         "no_tc_commit", "0", "Do not commit translated code");

KNOB<BOOL> KnobProf(KNOB_MODE_WRITEONCE, "pintool",
                    "prof", "0", "Prof run");

KNOB<BOOL> KnobInst(KNOB_MODE_WRITEONCE, "pintool",
                    "inst", "0", "Inst run");

/* ========================= from ex2.cpp =============================== */

class RoutineCount {
   public:
    RTN routine;
    ADDRINT routineAddr;
    ADDRINT imgAddr;
    string routineName;
    string imageName;
    UINT64 currRoutineCount;
    UINT64 instCount;
    RoutineCount() = default;  // default constructor
};

class BranchData {
   public:
    ADDRINT routineAddr;
    string routineName;
    ADDRINT branchAddr;
    ADDRINT branchTrgt;
    UINT64 currNumIteration;
    UINT64 lastNumIteration;
    UINT64 totalIterNum;
    UINT64 routineCounter;
    float meanTaken;
    UINT64 diffCounter;
    UINT64 counterLoopInvoked;
    UINT64 instCount;

    BranchData(ADDRINT routineAddr, string routineName, ADDRINT branchAddr, ADDRINT branchTrgt) : routineAddr(routineAddr), routineName(routineName), branchAddr(branchAddr), branchTrgt(branchTrgt), currNumIteration(0), lastNumIteration(0), totalIterNum(0), routineCounter(0), meanTaken(0), diffCounter(0), counterLoopInvoked(0), instCount(0){};

    BranchData() = default;
    BranchData(const BranchData &copy) {
        this->routineAddr = copy.routineAddr;
        this->routineName = copy.routineName;
        this->branchAddr = copy.branchAddr;
        this->branchTrgt = copy.branchTrgt;
        this->currNumIteration = copy.currNumIteration;
        this->lastNumIteration = copy.lastNumIteration;
        this->totalIterNum = copy.totalIterNum;
        this->routineCounter = copy.routineCounter;
        this->meanTaken = copy.meanTaken;
        this->diffCounter = copy.diffCounter;
        this->counterLoopInvoked = copy.counterLoopInvoked;
        this->instCount = copy.instCount;
    }

    BranchData &operator=(const BranchData &copy) {
        if (this == &copy)
            return *this;
        this->routineAddr = copy.routineAddr;
        this->routineName = copy.routineName;
        this->branchAddr = copy.branchAddr;
        this->branchTrgt = copy.branchTrgt;
        this->currNumIteration = copy.currNumIteration;
        this->lastNumIteration = copy.lastNumIteration;
        this->totalIterNum = copy.totalIterNum;
        this->routineCounter = copy.routineCounter;
        this->meanTaken = copy.meanTaken;
        this->diffCounter = copy.diffCounter;
        this->counterLoopInvoked = copy.counterLoopInvoked;
        this->instCount = copy.instCount;
        return *this;
    }
};

map<string, RoutineCount *> routinesMap;
map<ADDRINT, BranchData> branchMap;
map<ADDRINT, BranchData *> HotRoutines;
map<ADDRINT, RoutineCount *> HotRoutinesMap;

int remainder_cond_index_entry = 0;
int cond_index_entry = 0;
int unroll_jump_index_entry = 0;
int skip_jump_index_entry = 0;
int remainder_cond_index_target = 0;
int cond_index_target_entry = 0;
int unroll_jump_index_target = 0;
int skip_jump_index_target = 0;

VOID docount(UINT64 *counter) {
    (*counter)++;
}
VOID doloopcount(UINT64 *currNumIteration, UINT64 *counterLoopInvoked, BOOL flag, UINT64 *lastNumIteration, UINT64 *diffCounter, UINT64 *totalIterNum) {
    (*currNumIteration)++;
    (*totalIterNum)++;
    if (!flag) {
        (*counterLoopInvoked)++;
        if ((((*lastNumIteration) != (*currNumIteration)) && (*lastNumIteration) != 0)) {
            (*diffCounter)++;
        }
        (*lastNumIteration) = (*currNumIteration);
        (*currNumIteration) = 0;
    }
}

void unrolling_fallbackSort(IMG img);

const char *getPath(const char *path) {
    const char *file = strrchr(path, '/');
    if (!file)
        return path;
    return file + 1;
}

VOID Routine(RTN rtn, VOID *v) {
    if (rtn == RTN_Invalid()) {
        return;
    }
    RoutineCount *rc = new RoutineCount();
    rc->routineName = RTN_Name(rtn);
    rc->imageName = getPath(IMG_Name(SEC_Img(RTN_Sec(rtn))).c_str());
    rc->routineAddr = RTN_Address(rtn);
    rc->currRoutineCount = 0;
    rc->instCount = 0;

    if ((IMG_IsMainExecutable(SEC_Img(RTN_Sec(rtn))))) {
        pair<ADDRINT, RoutineCount *> tmp(rc->routineAddr, rc);
        HotRoutinesMap.insert(tmp);
    }

    routinesMap[rc->routineName] = rc;

    RTN_Open(rtn);

    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)docount, IARG_PTR, &(rc->currRoutineCount), IARG_END);

    for (INS inst = RTN_InsHead(rtn); INS_Valid(inst); inst = INS_Next(inst)) {
        if ((IMG_IsMainExecutable(SEC_Img(RTN_Sec(rtn))))) {
            INS_InsertCall(inst, IPOINT_BEFORE, (AFUNPTR)docount, IARG_PTR, &(rc->instCount), IARG_END);
        }
        if (INS_IsRet(inst))
            INS_InsertCall(inst, IPOINT_BEFORE, (AFUNPTR)docount, IARG_PTR, &(routinesMap[RTN_Name(rtn)]->currRoutineCount), IARG_END);

        if ((INS_IsDirectBranch(inst) && INS_HasFallThrough(inst)) && (INS_DirectControlFlowTargetAddress(inst) < INS_Address(inst))) {
            map<ADDRINT, BranchData>::iterator it1;
            BranchData Curr_Branch(RTN_Address(rtn), RTN_Name(rtn), INS_Address(inst), INS_DirectControlFlowTargetAddress(inst));
            it1 = branchMap.find(INS_Address(inst));
            if (it1 == branchMap.end())
                branchMap[INS_Address(inst)] = Curr_Branch;
            INS_InsertCall(inst, IPOINT_BEFORE, (AFUNPTR)doloopcount,
                           IARG_PTR, &(branchMap[INS_Address(inst)].currNumIteration),
                           IARG_PTR, &(branchMap[INS_Address(inst)].counterLoopInvoked),
                           IARG_BRANCH_TAKEN,
                           IARG_PTR, &(branchMap[INS_Address(inst)].lastNumIteration),
                           IARG_PTR, &(branchMap[INS_Address(inst)].diffCounter),
                           IARG_PTR, &(branchMap[INS_Address(inst)].totalIterNum), IARG_END);
        }
    }
    RTN_Close(rtn);
}

bool cmp(const pair<ADDRINT, BranchData> &left, const pair<ADDRINT, BranchData> &right) {
    return left.second.totalIterNum > right.second.totalIterNum;
}

bool cmp_2(const pair<ADDRINT, RoutineCount *> first, const pair<ADDRINT, RoutineCount *> second) {
    int left = first.second->instCount;
    int right = second.second->instCount;
    return left > right;
}

vector<pair<ADDRINT, RoutineCount *>> *my_sort(map<ADDRINT, RoutineCount *> *routinesMap) {
    vector<pair<ADDRINT, RoutineCount *>> *tmp = new vector<pair<ADDRINT, RoutineCount *>>;
    for (map<ADDRINT, RoutineCount *>::iterator it = routinesMap->begin(); it != routinesMap->end(); it++) {
        tmp->push_back(*it);
    }
    sort(tmp->begin(), tmp->end(), cmp_2);
    return tmp;
}

VOID Fini(INT32 code, VOID *v) {
    fstream fd_out;
    fd_out.open("loop-count.csv", ios::out);
    map<ADDRINT, BranchData>::iterator it1 = branchMap.begin();
    map<string, RoutineCount *>::iterator it2;
    vector<pair<ADDRINT, BranchData>> currVector(branchMap.size());
    vector<BranchData> HotRoutines(10);

    while (it1 != branchMap.end()) {
        if (!it1->second.counterLoopInvoked) {
            it1->second.counterLoopInvoked++;
        }
        UINT64 temp = it1->second.counterLoopInvoked;
        it1->second.meanTaken = (it1->second.totalIterNum) / (float)temp;
        it2 = routinesMap.find(it1->second.routineName);
        it1->second.routineCounter = it2->second->currRoutineCount;
        it1->second.instCount = it2->second->instCount;
        it1++;
    }

    copy(branchMap.begin(), branchMap.end(), currVector.begin());
    sort(currVector.begin(), currVector.end(), cmp);
    vector<pair<ADDRINT, RoutineCount *>> *temp_vector = my_sort(&HotRoutinesMap);

    for (unsigned int i = 0; i < currVector.size(); ++i) {
        if (currVector[i].second.totalIterNum != 0) {
            BranchData currInfo = currVector[i].second;
            fd_out << hex << "0x" << currInfo.branchTrgt << dec << ",";
            fd_out << currInfo.totalIterNum << ",";
            fd_out << currInfo.counterLoopInvoked << ",";
            fd_out << currInfo.meanTaken << ",";
            fd_out << currInfo.diffCounter << ",";
            fd_out << currInfo.routineName << ",";
            fd_out << hex << "0x" << currInfo.routineAddr << dec << ",";
            fd_out << currInfo.instCount << endl;
        }
    }
    fstream fd_hot_out;
    fd_hot_out.open("HotRoutines.csv", ios::out);
    int top_hot = 0;
    for (auto it = temp_vector->begin(); it != temp_vector->end(); ++it) {
        if (it->second->instCount > 0)
            fd_hot_out << setw(18) << hex << it->second->routineAddr << dec << endl;
        top_hot++;
        if (top_hot == 10)
            break;
    }
}

void getHotAddress(vector<ADDRINT> *routinesAddress) {
    ifstream file("HotRoutines.csv");
    string line;
    while (file.good()) {
        getline(file, line);
        ADDRINT address = AddrintFromString(line);
        routinesAddress->push_back(address);
    }
}
/* ===================================================================== */

std::ofstream *out = 0;

// For XED:
#if defined(TARGET_IA32E)
xed_state_t dstate = {XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b};
#else
xed_state_t dstate = {XED_MACHINE_MODE_LEGACY_32, XED_ADDRESS_WIDTH_32b};
#endif

//For XED: Pass in the proper length: 15 is the max. But if you do not want to
//cross pages, you can pass less than 15 bytes, of course, the
//instruction might not decode if not enough bytes are provided.
const unsigned int max_inst_len = XED_MAX_INSTRUCTION_BYTES;

ADDRINT lowest_sec_addr = 0;
ADDRINT highest_sec_addr = 0;

#define MAX_PROBE_JUMP_INSTR_BYTES 14

// tc containing the new code:
char *tc;
int tc_cursor = 0;

// instruction map with an entry for each new instruction:
typedef struct {
    ADDRINT orig_ins_addr;
    ADDRINT new_ins_addr;
    ADDRINT orig_targ_addr;
    bool hasNewTargAddr;
    char encoded_ins[XED_MAX_INSTRUCTION_BYTES];
    xed_category_enum_t category_enum;
    unsigned int size;
    int new_targ_entry;
} instr_map_t;

instr_map_t *instr_map = NULL;
int num_of_instr_map_entries = 0;
int max_ins_count = 0;

// total number of routines in the main executable module:
int max_rtn_count = 0;

// Tables of all candidate routines to be translated:
typedef struct {
    ADDRINT rtn_addr;
    USIZE rtn_size;
    int instr_map_entry;  // negative instr_map_entry means routine does not have a translation.
    bool isSafeForReplacedProbe;
} translated_rtn_t;

translated_rtn_t *translated_rtn;
int translated_rtn_num = 0;

/* ============================================================= */
/* Service dump routines                                         */
/* ============================================================= */

/*************************/
/* dump_all_image_instrs */
/*************************/
void dump_all_image_instrs(IMG img) {
    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn)) {
            // Open the RTN.
            RTN_Open(rtn);

            cerr << RTN_Name(rtn) << ":" << endl;

            for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins)) {
                cerr << "0x" << hex << INS_Address(ins) << ": " << INS_Disassemble(ins) << endl;
            }

            // Close the RTN.
            RTN_Close(rtn);
        }
    }
}

/*************************/
/* dump_instr_from_xedd */
/*************************/
void dump_instr_from_xedd(xed_decoded_inst_t *xedd, ADDRINT address) {
    // debug print decoded instr:
    char disasm_buf[2048];

    xed_uint64_t runtime_address = static_cast<UINT64>(address);  // set the runtime adddress for disassembly

    xed_format_context(XED_SYNTAX_INTEL, xedd, disasm_buf, sizeof(disasm_buf), static_cast<UINT64>(runtime_address), 0, 0);

    cerr << hex << address << ": " << disasm_buf << endl;
}

/************************/
/* dump_instr_from_mem */
/************************/
void dump_instr_from_mem(ADDRINT *address, ADDRINT new_addr) {
    char disasm_buf[2048];
    xed_decoded_inst_t new_xedd;

    xed_decoded_inst_zero_set_mode(&new_xedd, &dstate);

    xed_error_enum_t xed_code = xed_decode(&new_xedd, reinterpret_cast<UINT8 *>(address), max_inst_len);

    BOOL xed_ok = (xed_code == XED_ERROR_NONE);
    if (!xed_ok) {
        cerr << "invalid opcode" << endl;
        return;
    }

    xed_format_context(XED_SYNTAX_INTEL, &new_xedd, disasm_buf, 2048, static_cast<UINT64>(new_addr), 0, 0);

    cerr << "0x" << hex << new_addr << ": " << disasm_buf << endl;
}

/****************************/
/*  dump_entire_instr_map() */
/****************************/
void dump_entire_instr_map() {
    for (int i = 0; i < num_of_instr_map_entries; i++) {
        for (int j = 0; j < translated_rtn_num; j++) {
            if (translated_rtn[j].instr_map_entry == i) {
                RTN rtn = RTN_FindByAddress(translated_rtn[j].rtn_addr);

                if (rtn == RTN_Invalid()) {
                    cerr << "Unknwon"
                         << ":" << endl;
                } else {
                    cerr << RTN_Name(rtn) << ":" << endl;
                }
            }
        }
        dump_instr_from_mem((ADDRINT *)instr_map[i].new_ins_addr, instr_map[i].new_ins_addr);
    }
}

/**************************/
/* dump_instr_map_entry */
/**************************/
void dump_instr_map_entry(int instr_map_entry) {
    cerr << dec << instr_map_entry << ": ";
    cerr << " orig_ins_addr: " << hex << instr_map[instr_map_entry].orig_ins_addr;
    cerr << " new_ins_addr: " << hex << instr_map[instr_map_entry].new_ins_addr;
    cerr << " orig_targ_addr: " << hex << instr_map[instr_map_entry].orig_targ_addr;

    ADDRINT new_targ_addr;
    if (instr_map[instr_map_entry].new_targ_entry >= 0)
        new_targ_addr = instr_map[instr_map[instr_map_entry].new_targ_entry].new_ins_addr;
    else
        new_targ_addr = instr_map[instr_map_entry].orig_targ_addr;

    cerr << " new_targ_addr: " << hex << new_targ_addr;
    cerr << "    new instr:";
    dump_instr_from_mem((ADDRINT *)instr_map[instr_map_entry].encoded_ins, instr_map[instr_map_entry].new_ins_addr);
}

/*************/
/* dump_tc() */
/*************/
void dump_tc() {
    char disasm_buf[2048];
    xed_decoded_inst_t new_xedd;
    ADDRINT address = (ADDRINT)&tc[0];
    unsigned int size = 0;

    while (address < (ADDRINT)&tc[tc_cursor]) {
        address += size;

        xed_decoded_inst_zero_set_mode(&new_xedd, &dstate);

        xed_error_enum_t xed_code = xed_decode(&new_xedd, reinterpret_cast<UINT8 *>(address), max_inst_len);

        BOOL xed_ok = (xed_code == XED_ERROR_NONE);
        if (!xed_ok) {
            cerr << "invalid opcode" << endl;
            return;
        }

        xed_format_context(XED_SYNTAX_INTEL, &new_xedd, disasm_buf, 2048, static_cast<UINT64>(address), 0, 0);

        cerr << "0x" << hex << address << ": " << disasm_buf << endl;

        size = xed_decoded_inst_get_length(&new_xedd);
    }
}

/* ============================================================= */
/* Translation routines                                         */
/* ============================================================= */

/*************************/
/* add_new_instr_entry() */
/*************************/
int add_new_instr_entry(xed_decoded_inst_t *xedd, ADDRINT pc, unsigned int size) {
    // copy orig instr to instr map:
    ADDRINT orig_targ_addr = 0;

    if (xed_decoded_inst_get_length(xedd) != size) {
        cerr << "Invalid instruction decoding" << endl;
        return -1;
    }

    xed_uint_t disp_byts = xed_decoded_inst_get_branch_displacement_width(xedd);

    xed_int32_t disp;

    if (disp_byts > 0) {  // there is a branch offset.
        disp = xed_decoded_inst_get_branch_displacement(xedd);
        orig_targ_addr = pc + xed_decoded_inst_get_length(xedd) + disp;
    }

    // Converts the decoder request to a valid encoder request:
    xed_encoder_request_init_from_decode(xedd);

    unsigned int new_size = 0;

    xed_error_enum_t xed_error = xed_encode(xedd, reinterpret_cast<UINT8 *>(instr_map[num_of_instr_map_entries].encoded_ins), max_inst_len, &new_size);
    if (xed_error != XED_ERROR_NONE) {
        cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
        return -1;
    }

    // add a new entry in the instr_map:

    instr_map[num_of_instr_map_entries].orig_ins_addr = pc;
    instr_map[num_of_instr_map_entries].new_ins_addr = (ADDRINT)&tc[tc_cursor];  // set an initial estimated addr in tc
    instr_map[num_of_instr_map_entries].orig_targ_addr = orig_targ_addr;
    instr_map[num_of_instr_map_entries].hasNewTargAddr = false;
    instr_map[num_of_instr_map_entries].new_targ_entry = -1;
    instr_map[num_of_instr_map_entries].size = new_size;
    instr_map[num_of_instr_map_entries].category_enum = xed_decoded_inst_get_category(xedd);

    num_of_instr_map_entries++;

    // update expected size of tc:
    tc_cursor += new_size;

    if (num_of_instr_map_entries >= max_ins_count) {
        cerr << "out of memory for map_instr" << endl;
        return -1;
    }

    // debug print new encoded instr:
    if (KnobVerbose) {
        cerr << "    new instr:";
        dump_instr_from_mem((ADDRINT *)instr_map[num_of_instr_map_entries - 1].encoded_ins, instr_map[num_of_instr_map_entries - 1].new_ins_addr);
    }

    return new_size;
}

/*************************************************/
/* chain_all_direct_br_and_call_target_entries() */
/*************************************************/
int chain_all_direct_br_and_call_target_entries() {
    for (int i = 0; i < num_of_instr_map_entries; i++) {
        if (instr_map[i].orig_targ_addr == 0)
            continue;

        if (instr_map[i].hasNewTargAddr)
            continue;

        for (int j = 0; j < num_of_instr_map_entries; j++) {
            if (j == i)
                continue;

            if (instr_map[j].orig_ins_addr == instr_map[i].orig_targ_addr) {
                instr_map[i].hasNewTargAddr = true;
                instr_map[i].new_targ_entry = j;
                break;
            }
        }
    }

    return 0;
}

/**************************/
/* fix_rip_displacement() */
/**************************/
int fix_rip_displacement(int instr_map_entry) {
    //debug print:
    //dump_instr_map_entry(instr_map_entry);

    xed_decoded_inst_t xedd;
    xed_decoded_inst_zero_set_mode(&xedd, &dstate);

    xed_error_enum_t xed_code = xed_decode(&xedd, reinterpret_cast<UINT8 *>(instr_map[instr_map_entry].encoded_ins), max_inst_len);
    if (xed_code != XED_ERROR_NONE) {
        cerr << "ERROR: xed decode failed for instr at: "
             << "0x" << hex << instr_map[instr_map_entry].new_ins_addr << endl;
        return -1;
    }

    unsigned int memops = xed_decoded_inst_number_of_memory_operands(&xedd);

    if (instr_map[instr_map_entry].orig_targ_addr != 0)  // a direct jmp or call instruction.
        return 0;

    //cerr << "Memory Operands" << endl;
    bool isRipBase = false;
    xed_reg_enum_t base_reg = XED_REG_INVALID;
    xed_int64_t disp = 0;
    for (unsigned int i = 0; i < memops; i++) {
        base_reg = xed_decoded_inst_get_base_reg(&xedd, i);
        disp = xed_decoded_inst_get_memory_displacement(&xedd, i);

        if (base_reg == XED_REG_RIP) {
            isRipBase = true;
            break;
        }
    }

    if (!isRipBase)
        return 0;

    //xed_uint_t disp_byts = xed_decoded_inst_get_memory_displacement_width(xedd,i); // how many byts in disp ( disp length in byts - for example FFFFFFFF = 4
    xed_int64_t new_disp = 0;
    xed_uint_t new_disp_byts = 4;  // set maximal num of byts for now.

    unsigned int orig_size = xed_decoded_inst_get_length(&xedd);

    // modify rip displacement. use direct addressing mode:
    new_disp = instr_map[instr_map_entry].orig_ins_addr + disp + orig_size;  // xed_decoded_inst_get_length (&xedd_orig);
    xed_encoder_request_set_base0(&xedd, XED_REG_INVALID);

    //Set the memory displacement using a bit length
    xed_encoder_request_set_memory_displacement(&xedd, new_disp, new_disp_byts);

    unsigned int size = XED_MAX_INSTRUCTION_BYTES;
    unsigned int new_size = 0;

    // Converts the decoder request to a valid encoder request:
    xed_encoder_request_init_from_decode(&xedd);

    xed_error_enum_t xed_error = xed_encode(&xedd, reinterpret_cast<UINT8 *>(instr_map[instr_map_entry].encoded_ins), size, &new_size);  // &instr_map[i].size
    if (xed_error != XED_ERROR_NONE) {
        cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
        dump_instr_map_entry(instr_map_entry);
        return -1;
    }

    if (KnobVerbose) {
        dump_instr_map_entry(instr_map_entry);
    }

    return new_size;
}

/************************************/
/* fix_direct_br_call_to_orig_addr */
/************************************/
int fix_direct_br_call_to_orig_addr(int instr_map_entry) {
    xed_decoded_inst_t xedd;
    xed_decoded_inst_zero_set_mode(&xedd, &dstate);

    xed_error_enum_t xed_code = xed_decode(&xedd, reinterpret_cast<UINT8 *>(instr_map[instr_map_entry].encoded_ins), max_inst_len);
    if (xed_code != XED_ERROR_NONE) {
        cerr << "ERROR: xed decode failed for instr at: "
             << "0x" << hex << instr_map[instr_map_entry].new_ins_addr << endl;
        return -1;
    }

    xed_category_enum_t category_enum = xed_decoded_inst_get_category(&xedd);

    if (category_enum != XED_CATEGORY_CALL && category_enum != XED_CATEGORY_UNCOND_BR) {
        cerr << "ERROR: Invalid direct jump from translated code to original code in rotuine: "
             << RTN_Name(RTN_FindByAddress(instr_map[instr_map_entry].orig_ins_addr)) << endl;
        dump_instr_map_entry(instr_map_entry);
        return -1;
    }

    // check for cases of direct jumps/calls back to the orginal target address:
    if (instr_map[instr_map_entry].new_targ_entry >= 0) {
        cerr << "ERROR: Invalid jump or call instruction" << endl;
        return -1;
    }

    unsigned int ilen = XED_MAX_INSTRUCTION_BYTES;
    unsigned int olen = 0;

    xed_encoder_instruction_t enc_instr;

    ADDRINT new_disp = (ADDRINT)&instr_map[instr_map_entry].orig_targ_addr -
                       instr_map[instr_map_entry].new_ins_addr -
                       xed_decoded_inst_get_length(&xedd);

    if (category_enum == XED_CATEGORY_CALL)
        xed_inst1(&enc_instr, dstate,
                  XED_ICLASS_CALL_NEAR, 64,
                  xed_mem_bd(XED_REG_RIP, xed_disp(new_disp, 32), 64));

    if (category_enum == XED_CATEGORY_UNCOND_BR)
        xed_inst1(&enc_instr, dstate,
                  XED_ICLASS_JMP, 64,
                  xed_mem_bd(XED_REG_RIP, xed_disp(new_disp, 32), 64));

    xed_encoder_request_t enc_req;

    xed_encoder_request_zero_set_mode(&enc_req, &dstate);
    xed_bool_t convert_ok = xed_convert_to_encoder_request(&enc_req, &enc_instr);
    if (!convert_ok) {
        cerr << "conversion to encode request failed" << endl;
        return -1;
    }

    xed_error_enum_t xed_error = xed_encode(&enc_req, reinterpret_cast<UINT8 *>(instr_map[instr_map_entry].encoded_ins), ilen, &olen);
    if (xed_error != XED_ERROR_NONE) {
        cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
        dump_instr_map_entry(instr_map_entry);
        return -1;
    }

    // handle the case where the original instr size is different from new encoded instr:
    if (olen != xed_decoded_inst_get_length(&xedd)) {
        new_disp = (ADDRINT)&instr_map[instr_map_entry].orig_targ_addr -
                   instr_map[instr_map_entry].new_ins_addr - olen;

        if (category_enum == XED_CATEGORY_CALL)
            xed_inst1(&enc_instr, dstate,
                      XED_ICLASS_CALL_NEAR, 64,
                      xed_mem_bd(XED_REG_RIP, xed_disp(new_disp, 32), 64));

        if (category_enum == XED_CATEGORY_UNCOND_BR)
            xed_inst1(&enc_instr, dstate,
                      XED_ICLASS_JMP, 64,
                      xed_mem_bd(XED_REG_RIP, xed_disp(new_disp, 32), 64));

        xed_encoder_request_zero_set_mode(&enc_req, &dstate);
        xed_bool_t convert_ok = xed_convert_to_encoder_request(&enc_req, &enc_instr);
        if (!convert_ok) {
            cerr << "conversion to encode request failed" << endl;
            return -1;
        }

        xed_error = xed_encode(&enc_req, reinterpret_cast<UINT8 *>(instr_map[instr_map_entry].encoded_ins), ilen, &olen);
        if (xed_error != XED_ERROR_NONE) {
            cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
            dump_instr_map_entry(instr_map_entry);
            return -1;
        }
    }

    // debug prints:
    if (KnobVerbose) {
        dump_instr_map_entry(instr_map_entry);
    }

    instr_map[instr_map_entry].hasNewTargAddr = true;
    return olen;
}

/***********************************/
/* fix_direct_br_call_displacement */
/***********************************/
int fix_direct_br_call_displacement(int instr_map_entry) {
    xed_decoded_inst_t xedd;
    xed_decoded_inst_zero_set_mode(&xedd, &dstate);

    xed_error_enum_t xed_code = xed_decode(&xedd, reinterpret_cast<UINT8 *>(instr_map[instr_map_entry].encoded_ins), max_inst_len);
    if (xed_code != XED_ERROR_NONE) {
        cerr << "ERROR: xed decode failed for instr at: "
             << "0x" << hex << instr_map[instr_map_entry].new_ins_addr << endl;
        return -1;
    }

    xed_int32_t new_disp = 0;
    unsigned int size = XED_MAX_INSTRUCTION_BYTES;
    unsigned int new_size = 0;

    xed_category_enum_t category_enum = xed_decoded_inst_get_category(&xedd);

    if (category_enum != XED_CATEGORY_CALL && category_enum != XED_CATEGORY_COND_BR && category_enum != XED_CATEGORY_UNCOND_BR) {
        cerr << "ERROR: unrecognized branch displacement" << endl;
        return -1;
    }

    // fix branches/calls to original targ addresses:
    if (instr_map[instr_map_entry].new_targ_entry < 0) {
        int rc = fix_direct_br_call_to_orig_addr(instr_map_entry);
        return rc;
    }

    ADDRINT new_targ_addr;
    new_targ_addr = instr_map[instr_map[instr_map_entry].new_targ_entry].new_ins_addr;

    new_disp = (new_targ_addr - instr_map[instr_map_entry].new_ins_addr) - instr_map[instr_map_entry].size;  // orig_size;

    xed_uint_t new_disp_byts = 4;  // num_of_bytes(new_disp);  ???

    // the max displacement size of loop instructions is 1 byte:
    xed_iclass_enum_t iclass_enum = xed_decoded_inst_get_iclass(&xedd);
    if (iclass_enum == XED_ICLASS_LOOP || iclass_enum == XED_ICLASS_LOOPE || iclass_enum == XED_ICLASS_LOOPNE) {
        new_disp_byts = 1;
    }

    // the max displacement size of jecxz instructions is ???:
    xed_iform_enum_t iform_enum = xed_decoded_inst_get_iform_enum(&xedd);
    if (iform_enum == XED_IFORM_JRCXZ_RELBRb) {
        new_disp_byts = 1;
    }

    // Converts the decoder request to a valid encoder request:
    xed_encoder_request_init_from_decode(&xedd);

    //Set the branch displacement:
    xed_encoder_request_set_branch_displacement(&xedd, new_disp, new_disp_byts);

    xed_uint8_t enc_buf[XED_MAX_INSTRUCTION_BYTES];
    unsigned int max_size = XED_MAX_INSTRUCTION_BYTES;

    xed_error_enum_t xed_error = xed_encode(&xedd, enc_buf, max_size, &new_size);
    if (xed_error != XED_ERROR_NONE) {
        cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
        char buf[2048];
        xed_format_context(XED_SYNTAX_INTEL, &xedd, buf, 2048, static_cast<UINT64>(instr_map[instr_map_entry].orig_ins_addr), 0, 0);
        cerr << " instr: "
             << "0x" << hex << instr_map[instr_map_entry].orig_ins_addr << " : " << buf << endl;
        return -1;
    }

    new_targ_addr = instr_map[instr_map[instr_map_entry].new_targ_entry].new_ins_addr;

    new_disp = new_targ_addr - (instr_map[instr_map_entry].new_ins_addr + new_size);  // this is the correct displacemnet.

    //Set the branch displacement:
    xed_encoder_request_set_branch_displacement(&xedd, new_disp, new_disp_byts);

    xed_error = xed_encode(&xedd, reinterpret_cast<UINT8 *>(instr_map[instr_map_entry].encoded_ins), size, &new_size);  // &instr_map[i].size
    if (xed_error != XED_ERROR_NONE) {
        cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
        dump_instr_map_entry(instr_map_entry);
        return -1;
    }

    //debug print of new instruction in tc:
    if (KnobVerbose) {
        dump_instr_map_entry(instr_map_entry);
    }

    return new_size;
}

/************************************/
/* fix_instructions_displacements() */
/************************************/
int fix_instructions_displacements() {
    // fix displacemnets of direct branch or call instructions:

    int size_diff = 0;

    do {
        size_diff = 0;

        if (KnobVerbose) {
            cerr << "starting a pass of fixing instructions displacements: " << endl;
        }

        for (int i = 0; i < num_of_instr_map_entries; i++) {
            instr_map[i].new_ins_addr += size_diff;

            int rc = 0;

            // fix rip displacement:
            rc = fix_rip_displacement(i);
            if (rc < 0)
                return -1;

            if (rc > 0) {  // this was a rip-based instruction which was fixed.

                if (instr_map[i].size != (unsigned int)rc) {
                    size_diff += (rc - instr_map[i].size);
                    instr_map[i].size = (unsigned int)rc;
                }

                continue;
            }

            // check if it is a direct branch or a direct call instr:
            if (instr_map[i].orig_targ_addr == 0) {
                continue;  // not a direct branch or a direct call instr.
            }

            // fix instr displacement:
            rc = fix_direct_br_call_displacement(i);
            if (rc < 0)
                return -1;

            if (instr_map[i].size != (unsigned int)rc) {
                size_diff += (rc - instr_map[i].size);
                instr_map[i].size = (unsigned int)rc;
            }

        }  // end int i=0; i ..

    } while (size_diff != 0);

    return 0;
}

/*****************************************/
/* find_candidate_rtns_for_translation() */
/*****************************************/
int find_candidate_rtns_for_translation(IMG img) {
    int rc;
    // go over routines and check if they are candidates for translation and mark them for translation:
    vector<ADDRINT> hotRoutinseAddress;
    getHotAddress(&hotRoutinseAddress);
    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
        if (!SEC_IsExecutable(sec) || SEC_IsWriteable(sec) || !SEC_Address(sec))
            continue;

        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn)) {
            if (rtn == RTN_Invalid()) {
                cerr << "Warning: invalid routine " << RTN_Name(rtn) << endl;
                continue;
            }
            if (!(IMG_IsMainExecutable(SEC_Img(RTN_Sec(rtn))))) {
                continue;
            }
            if (!count(hotRoutinseAddress.begin(), hotRoutinseAddress.end(), RTN_Address(rtn))) {
                continue;
            }
            translated_rtn[translated_rtn_num].rtn_addr = RTN_Address(rtn);
            translated_rtn[translated_rtn_num].rtn_size = RTN_Size(rtn);
            translated_rtn[translated_rtn_num].instr_map_entry = num_of_instr_map_entries;
            translated_rtn[translated_rtn_num].isSafeForReplacedProbe = true;

            // Open the RTN.
            RTN_Open(rtn);

            for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins)) {
                //debug print of orig instruction:
                if (KnobVerbose) {
                    cerr << "old instr: ";
                    cerr << "0x" << hex << INS_Address(ins) << ": " << INS_Disassemble(ins) << endl;
                    //xed_print_hex_line(reinterpret_cast<UINT8*>(INS_Address (ins)), INS_Size(ins));
                }

                ADDRINT addr = INS_Address(ins);

                xed_decoded_inst_t xedd;
                xed_error_enum_t xed_code;

                xed_decoded_inst_zero_set_mode(&xedd, &dstate);

                xed_code = xed_decode(&xedd, reinterpret_cast<UINT8 *>(addr), max_inst_len);
                if (xed_code != XED_ERROR_NONE) {
                    cerr << "ERROR: xed decode failed for instr at: "
                         << "0x" << hex << addr << endl;
                    translated_rtn[translated_rtn_num].instr_map_entry = -1;
                    break;
                }

                // Add instr into instr map:
                rc = add_new_instr_entry(&xedd, INS_Address(ins), INS_Size(ins));
                if (rc < 0) {
                    cerr << "ERROR: failed during instructon translation." << endl;
                    translated_rtn[translated_rtn_num].instr_map_entry = -1;
                    break;
                }
            }  // end for INS...

            // debug print of routine name:
            if (KnobVerbose) {
                cerr << "rtn name: " << RTN_Name(rtn) << " : " << dec << translated_rtn_num << endl;
            }
            // Close the RTN.
            RTN_Close(rtn);

            translated_rtn_num++;
        }  // end for RTN..
    }      // end for SEC...

    unrolling_fallbackSort(img);  // Handling fallbackSort
    return 0;
}

/***************************/
/* int copy_instrs_to_tc() */
/***************************/
int copy_instrs_to_tc() {
    int cursor = 0;

    for (int i = 0; i < num_of_instr_map_entries; i++) {
        if ((ADDRINT)&tc[cursor] != instr_map[i].new_ins_addr) {
            cerr << "ERROR: Non-matching instruction addresses: " << hex << (ADDRINT)&tc[cursor] << " vs. " << instr_map[i].new_ins_addr << endl;
            return -1;
        }

        memcpy(&tc[cursor], &instr_map[i].encoded_ins, instr_map[i].size);

        cursor += instr_map[i].size;
    }

    return 0;
}

/*************************************/
/* void commit_translated_routines() */
/*************************************/
inline void commit_translated_routines() {
    // Commit the translated functions:
    // Go over the candidate functions and replace the original ones by their new successfully translated ones:

    for (int i = 0; i < translated_rtn_num; i++) {
        //replace function by new function in tc

        if (translated_rtn[i].instr_map_entry >= 0) {
            if (translated_rtn[i].rtn_size > MAX_PROBE_JUMP_INSTR_BYTES && translated_rtn[i].isSafeForReplacedProbe) {
                RTN rtn = RTN_FindByAddress(translated_rtn[i].rtn_addr);

                //debug print:
                if (rtn == RTN_Invalid()) {
                    cerr << "committing rtN: Unknown";
                } else {
                    cerr << "committing rtN: " << RTN_Name(rtn);
                }
                cerr << " from: 0x" << hex << RTN_Address(rtn) << " to: 0x" << hex << instr_map[translated_rtn[i].instr_map_entry].new_ins_addr << endl;

                if (RTN_IsSafeForProbedReplacement(rtn)) {
                    AFUNPTR origFptr = RTN_ReplaceProbed(rtn, (AFUNPTR)instr_map[translated_rtn[i].instr_map_entry].new_ins_addr);

                    if (origFptr == NULL) {
                        cerr << "RTN_ReplaceProbed failed.";
                    } else {
                        cerr << "RTN_ReplaceProbed succeeded. ";
                    }
                    cerr << " orig routine addr: 0x" << hex << translated_rtn[i].rtn_addr
                         << " replacement routine addr: 0x" << hex << instr_map[translated_rtn[i].instr_map_entry].new_ins_addr << endl;

                    dump_instr_from_mem((ADDRINT *)translated_rtn[i].rtn_addr, translated_rtn[i].rtn_addr);
                }
            }
        }
    }
}

/****************************/
/* allocate_and_init_memory */
/****************************/
int allocate_and_init_memory(IMG img) {
    // Calculate size of executable sections and allocate required memory:
    //
    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
        if (!SEC_IsExecutable(sec) || SEC_IsWriteable(sec) || !SEC_Address(sec))
            continue;

        if (!lowest_sec_addr || lowest_sec_addr > SEC_Address(sec))
            lowest_sec_addr = SEC_Address(sec);

        if (highest_sec_addr < SEC_Address(sec) + SEC_Size(sec))
            highest_sec_addr = SEC_Address(sec) + SEC_Size(sec);

        // need to avouid using RTN_Open as it is expensive...
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn)) {
            if (rtn == RTN_Invalid())
                continue;

            max_ins_count += RTN_NumIns(rtn);
            max_rtn_count++;
        }
    }

    max_ins_count *= 4;  // estimating that the num of instrs of the inlined functions will not exceed the total nunmber of the entire code.

    // Allocate memory for the instr map needed to fix all branch targets in translated routines:
    instr_map = (instr_map_t *)calloc(max_ins_count, sizeof(instr_map_t));
    if (instr_map == NULL) {
        perror("calloc");
        return -1;
    }

    // Allocate memory for the array of candidate routines containing inlineable function calls:
    // Need to estimate size of inlined routines.. ???
    translated_rtn = (translated_rtn_t *)calloc(max_rtn_count, sizeof(translated_rtn_t));
    if (translated_rtn == NULL) {
        perror("calloc");
        return -1;
    }

    // get a page size in the system:
    int pagesize = sysconf(_SC_PAGE_SIZE);
    if (pagesize == -1) {
        perror("sysconf");
        return -1;
    }

    ADDRINT text_size = (highest_sec_addr - lowest_sec_addr) * 2 + pagesize * 4;

    int tclen = 2 * text_size + pagesize * 4;  // need a better estimate???

    // Allocate the needed tc with RW+EXEC permissions and is not located in an address that is more than 32bits afar:
    char *addr = (char *)mmap(NULL, tclen, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    if ((ADDRINT)addr == 0xffffffffffffffff) {
        cerr << "failed to allocate tc" << endl;
        return -1;
    }

    tc = (char *)addr;
    return 0;
}

/* ============================================ */
/* Main translation routine                     */
/* ============================================ */
VOID ImageLoad(IMG img, VOID *v) {
    // debug print of all images' instructions
    //dump_all_image_instrs(img);

    // Step 0: Check the image and the CPU:
    if (!IMG_IsMainExecutable(img))
        return;

    int rc = 0;

    // step 1: Check size of executable sections and allocate required memory:
    rc = allocate_and_init_memory(img);
    if (rc < 0)
        return;

    cout << "after memory allocation" << endl;

    // Step 2: go over all routines and identify candidate routines and copy their code into the instr map IR:
    rc = find_candidate_rtns_for_translation(img);
    if (rc < 0)
        return;

    cout << "after identifying candidate routines" << endl;

    // Step 3: Chaining - calculate direct branch and call instructions to point to corresponding target instr entries:
    rc = chain_all_direct_br_and_call_target_entries();
    if (rc < 0)
        return;

    cout << "after calculate direct br targets" << endl;

    // Step 4: fix rip-based, direct branch and direct call displacements:
    rc = fix_instructions_displacements();
    if (rc < 0)
        return;

    cout << "after fix instructions displacements" << endl;

    // Step 5: write translated routines to new tc:
    rc = copy_instrs_to_tc();
    if (rc < 0)
        return;

    cout << "after write all new instructions to memory tc" << endl;

    if (KnobDumpTranslatedCode) {
        cerr << "Translation Cache dump:" << endl;
        dump_tc();  // dump the entire tc

        cerr << endl
             << "instructions map dump:" << endl;
        dump_entire_instr_map();  // dump all translated instructions in map_instr
    }

    // Step 6: Commit the translated routines:
    //Go over the candidate functions and replace the original ones by their new successfully translated ones:
    if (!KnobDoNotCommitTranslatedCode) {
        commit_translated_routines();
        cout << "after commit translated routines" << endl;
    }
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */
INT32 Usage() {
    cerr << "This tool translated routines of an Intel(R) 64 binary"
         << endl;
    cerr << KNOB_BASE::StringKnobSummary();
    cerr << endl;
    return -1;
}

bool fexists(const char *filename) {
    ifstream ifile(filename);
    return ifile;
}

/*****************************************/
/* inCsv(RTN rtn) */
/*****************************************/

bool inCsv(string const &rtn) {
    ifstream file("HotRoutines.csv");  //declare file stream
    string value;
    while (file.good()) {
        getline(file, value);
        //cout << "in CSV" << value << endl;
        if (value == rtn) return true;
    }
    return false;
}

/********************************************************/
/* Insert unconditional jump (for the remainder usage) */
/********************************************************/
int insert_uncon_jump(ADDRINT addr) {
    xed_decoded_inst_t xedd;
    xed_decoded_inst_zero_set_mode(&xedd, &dstate);

    unsigned int ilen = XED_MAX_INSTRUCTION_BYTES;
    unsigned int olen = 0;

    xed_error_enum_t xed_code = xed_decode(&xedd,
                                           reinterpret_cast<UINT8 *>(addr), max_inst_len);
    if (xed_code != XED_ERROR_NONE) {
        cerr << "ERROR: xed decode failed for instr at: "
             << "0x" << hex << addr
             << endl;
        return -1;
    }

    xed_encoder_instruction_t enc_instr;
    xed_inst1(&enc_instr, dstate, XED_ICLASS_JMP, 64,
              xed_mem_bd(XED_REG_RIP, xed_disp(ilen, 32), 64));

    xed_encoder_request_t enc_req;

    xed_encoder_request_zero_set_mode(&enc_req, &dstate);
    xed_bool_t convert_ok = xed_convert_to_encoder_request(&enc_req,
                                                           &enc_instr);
    if (!convert_ok) {
        cerr << "conversion to encode request failed" << endl;
        return -1;
    }
    xed_uint8_t enc_buf[XED_MAX_INSTRUCTION_BYTES];
    xed_error_enum_t xed_error = xed_encode(&enc_req,
                                            reinterpret_cast<UINT8 *>(enc_buf), ilen, &olen);
    if (xed_error != XED_ERROR_NONE) {
        cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
        return -1;
    }
    xed_decoded_inst_zero_set_mode(&xedd, &dstate);

    xed_code = xed_decode(&xedd, reinterpret_cast<UINT8 *>(enc_buf),
                          max_inst_len);
    if (xed_code != XED_ERROR_NONE) {
        cerr << "ERROR: XED decode failed" << addr << "instruction" << endl;
        return -1;
    }

    int InsSize = xed_decoded_inst_get_length(&xedd);
    int rc = add_new_instr_entry(&xedd, 0, InsSize);
    if (rc < 0) {
        cerr << "ERROR: failed during instruction translation." << endl;
        translated_rtn[translated_rtn_num].instr_map_entry = -1;
        return -1;
    }

    return 0;
}

/*****************************************/
/* Jump Less encoding + decoding */
/*****************************************/
int insert_jl(ADDRINT addr) {
    xed_decoded_inst_t xedd;
    xed_decoded_inst_zero_set_mode(&xedd, &dstate);

    xed_error_enum_t xed_code = xed_decode(&xedd,
                                           reinterpret_cast<UINT8 *>(addr), max_inst_len);
    if (xed_code != XED_ERROR_NONE) {
        cerr << "ERROR: xed decode failed for instr at: "
             << "0x" << hex << addr
             << endl;
        return -1;
    }

    xed_encoder_request_init_from_decode(&xedd);
    xed_encoder_request_set_branch_displacement(&xedd, INVALID, 4);

    int InsSize = xed_decoded_inst_get_length(&xedd);
    int rc = add_new_instr_entry(&xedd, 0, InsSize);
    if (rc < 0) {
        cerr << "ERROR: failed during instruction translation." << endl;
        translated_rtn[translated_rtn_num].instr_map_entry = -1;
        return -1;
    }

    return 0;
}

/*****************************************/
/*Insert a new instruction*/
/*****************************************/
int insert_instruction(ADDRINT addr, xed_encoder_operand_t m_oper) {
    xed_decoded_inst_t xedd;
    xed_decoded_inst_zero_set_mode(&xedd, &dstate);

    unsigned int ilen = XED_MAX_INSTRUCTION_BYTES;
    unsigned int olen = 0;

    xed_error_enum_t xed_code = xed_decode(&xedd,
                                           reinterpret_cast<UINT8 *>(addr), max_inst_len);
    if (xed_code != XED_ERROR_NONE) {
        cerr << "ERROR: xed decode failed for instr at: "
             << "0x" << hex << addr
             << endl;
        return -1;
    }

    xed_encoder_instruction_t enc_instr;
    xed_inst2(&enc_instr, dstate, xed_decoded_inst_get_iclass(&xedd), 32,
              xed_reg(XED_REG_EBX), m_oper);

    xed_encoder_request_t enc_req;

    xed_encoder_request_zero_set_mode(&enc_req, &dstate);
    xed_bool_t convert_ok = xed_convert_to_encoder_request(&enc_req,
                                                           &enc_instr);
    if (!convert_ok) {
        cerr << "conversion to encode request failed" << endl;
        return -1;
    }
    xed_uint8_t enc_buf[XED_MAX_INSTRUCTION_BYTES];
    xed_error_enum_t xed_error = xed_encode(&enc_req,
                                            reinterpret_cast<UINT8 *>(enc_buf), ilen, &olen);
    if (xed_error != XED_ERROR_NONE) {
        cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
        return -1;
    }

    xed_decoded_inst_zero_set_mode(&xedd, &dstate);

    xed_code = xed_decode(&xedd, reinterpret_cast<UINT8 *>(enc_buf),
                          max_inst_len);
    if (xed_code != XED_ERROR_NONE) {
        cerr << "ERROR: XED decode failed" << addr << "instruction" << endl;
        return -1;
    }

    int InsSize = xed_decoded_inst_get_length(&xedd);
    int rc = add_new_instr_entry(&xedd, 0, InsSize);
    if (rc < 0) {
        cerr << "ERROR: failed during instruction translation." << endl;
        translated_rtn[translated_rtn_num].instr_map_entry = -1;
        return -1;
    }

    return 0;
}

void add_new_cmds(INS ins) {
    int rc = 0;

    //mov 0x18(%rbp) eax

    xed_decoded_inst_t xedd;
    xed_decoded_inst_zero_set_mode(&xedd, &dstate);
    xed_decode(&xedd, reinterpret_cast<UINT8 *>(INS_Address(ins)), max_inst_len);
    rc = add_new_instr_entry(&xedd, INS_Address(ins), INS_Size(ins));
    if (rc < 0) {
        cerr << "ERROR: failed during instruction translation." << endl;
        translated_rtn[translated_rtn_num].instr_map_entry = -1;
        return;
    }
    //mov -0x86c(%rbp),%ebx
    xed_encoder_operand_t right_operand = xed_mem_bd(XED_REG_RIP, xed_disp(-0x86c, 32), 32);
    insert_instruction(MOV_ADDRESS, right_operand);

    // addl -4 %ebx

    right_operand = xed_imm0(-4, 32);
    insert_instruction(ADD_ADDRESS, right_operand);
    cond_index_target_entry = num_of_instr_map_entries - 1;  //

    //CMP %ebx, %eax
    right_operand = xed_reg(XED_REG_EAX);
    insert_instruction(CMP_ADDRESS, right_operand);

    //jl jump less

    insert_jl(END_ADDRESS);
    remainder_cond_index_entry = num_of_instr_map_entries - 1;
}
void update_conditions() {
    skip_jump_index_target = num_of_instr_map_entries;  // skip remainder jump
    instr_map[skip_jump_index_entry].new_targ_entry = skip_jump_index_target;
    instr_map[skip_jump_index_entry].hasNewTargAddr = true;

    unroll_jump_index_entry = num_of_instr_map_entries - 1;  //unrolling jump of the remainder
    instr_map[unroll_jump_index_entry].new_targ_entry = unroll_jump_index_target;
    instr_map[unroll_jump_index_entry].hasNewTargAddr = true;
}

/*****************************************/
/* unrolling_fallbackSort(IMG img) */
/*****************************************/

void unrolling_fallbackSort(IMG img) {
    cout << "started_unrolling" << endl;
    int rc = 0;
    bool adding_new_operations = true;
    bool isUnrolling = true;
    int unrollingNum = 1;

    RTN rtn = RTN_FindByName(img, "fallbackSort");  // finding the routine

    if (rtn == RTN_Invalid()) {
        cout << "Warning: invalid routine " << RTN_Name(rtn) << endl;
        return;
    }

    translated_rtn[translated_rtn_num].rtn_addr = RTN_Address(rtn);
    translated_rtn[translated_rtn_num].rtn_size = RTN_Size(rtn);
    translated_rtn[translated_rtn_num].instr_map_entry = num_of_instr_map_entries;
    translated_rtn[translated_rtn_num].isSafeForReplacedProbe = true;

    // Open the RTN.
    RTN_Open(rtn);
    INS TopRoll = RTN_InsHead(rtn);
    INS ins;
    for (ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins)) {
        if (KnobVerbose) {
            cerr << "old instr: ";
            cerr << "0x" << hex << INS_Address(ins) << ": "
                 << INS_Disassemble(ins) << endl;
        }

        ADDRINT addr = INS_Address(ins);

        if (INS_Address(ins) == START_ADDRESS) {
            TopRoll = ins;

            if (adding_new_operations) {
                add_new_cmds(ins);  // add my cmds
                adding_new_operations = false;
            }
        }

        xed_decoded_inst_t xedd;
        xed_error_enum_t xed_code;
        xed_decoded_inst_zero_set_mode(&xedd, &dstate);

        xed_code = xed_decode(&xedd, reinterpret_cast<UINT8 *>(INS_Address(ins)),
                              max_inst_len);
        if (xed_code != XED_ERROR_NONE) {
            cerr << "ERROR: xed decode failed for instr at: "
                 << "0x" << hex
                 << addr << endl;
            translated_rtn[translated_rtn_num].instr_map_entry = -1;
            break;
        }

        if (INS_Address(ins) == CMP_ADDRESS && unrollingNum > 0 && unrollingNum < UNROLL_COUNT) {
            unrollingNum++;
            ins = TopRoll;
            continue;
        }

        // Add instr into instr map:
        rc = add_new_instr_entry(&xedd, INS_Address(ins), INS_Size(ins));
        if (rc < 0) {
            cerr << "ERROR: failed during instructon translation." << endl;
            translated_rtn[translated_rtn_num].instr_map_entry = -1;
            break;
        }

        if (isUnrolling == false && addr == CMP_ADDRESS) {
            instr_map[remainder_cond_index_entry].new_targ_entry = num_of_instr_map_entries - 1;  // jump to the cmp of the remainder
            instr_map[remainder_cond_index_entry].hasNewTargAddr = true;
        }

        if (isUnrolling == true && addr == END_ADDRESS) {
            cond_index_entry = num_of_instr_map_entries - 1;
            instr_map[cond_index_entry].new_targ_entry = cond_index_target_entry;
            instr_map[cond_index_entry].hasNewTargAddr = true;
            insert_uncon_jump(END_ADDRESS);
            skip_jump_index_entry = num_of_instr_map_entries - 1;  // skipping the remainder
            unroll_jump_index_target = num_of_instr_map_entries;   // condition for the remainder (head of the remainder)
            ins = TopRoll;                                         // to get the code of the remainder
            isUnrolling = false;
        }
    }

    update_conditions();

    if (KnobVerbose) {
        cerr << "rtn name: " << RTN_Name(rtn) << " : " << dec << translated_rtn_num
             << endl;
    }
    RTN_Close(rtn);

    cout << "finished_unrolling" << endl;
    return;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char *argv[]) {
    if (PIN_Init(argc, argv)) {
        return Usage();
    }
    PIN_InitSymbols();
    if (KnobProf) {
        // Register Routine to be called to instrument rtn
        RTN_AddInstrumentFunction(Routine, 0);

        // Register Fini to be called when the application exits
        PIN_AddFiniFunction(Fini, 0);
        // Start the program, never returns
        PIN_StartProgram();
        return 0;
    }

    else if (KnobInst) {
        if (fexists("HotRoutines.csv")) {
            // Register ImageLoad
            IMG_AddInstrumentFunction(ImageLoad, 0);
            // Start the program, never returns
            PIN_StartProgramProbed();
            return 0;
        } else {
            cout << "no profile exists" << endl;
            return 0;
        }
    } else {
        // Register Routine to be called to instrument rtn
        cout << "NO knob found" << endl;
        // Register Fini to be called when the application exits
        // Start the program, never returns
        PIN_StartProgram();

        return 0;
    }

    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */