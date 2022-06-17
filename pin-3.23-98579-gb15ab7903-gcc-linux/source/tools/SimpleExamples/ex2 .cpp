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
#include <pin.H>
#include <string.h>

#include <algorithm>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <vector>

using namespace std;

/* ===================================================================== */
/* Global Variables */
/* ===================================================================== */

// Saves all data for each csv row
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

    BranchData(ADDRINT routineAddr, string routineName, ADDRINT branchAddr, ADDRINT branchTrgt) : routineAddr(routineAddr), routineName(routineName), branchAddr(branchAddr), branchTrgt(branchTrgt), currNumIteration(0), lastNumIteration(0), totalIterNum(0), routineCounter(0), meanTaken(0), diffCounter(0), counterLoopInvoked(0),instCount(0) {};

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

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32
Usage() {
    cerr << "This tool prints out the number of dynamic instructions executed to stderr.\n"
            "\n";

    cerr << KNOB_BASE::StringKnobSummary();

    cerr << endl;

    return -1;
}

/* ===================================================================== */

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

/* ===================================================================== */

const char *getPath(const char *path) {
    const char *file = strrchr(path, '/');
    if (!file)
        return path;
    return file + 1;
}

/* ===================================================================== */

VOID Routine(RTN rtn, VOID *v) {
    RoutineCount *rc = new RoutineCount();
    rc->routineName = RTN_Name(rtn);
    rc->imageName = getPath(IMG_Name(SEC_Img(RTN_Sec(rtn))).c_str());
    rc->routineAddr = RTN_Address(rtn);
    rc->currRoutineCount = 0;

    routinesMap[rc->routineName] = rc;
    RTN_Open(rtn);

    for (INS inst = RTN_InsHead(rtn); INS_Valid(inst); inst = INS_Next(inst)) {
		INS_InsertCall(inst, IPOINT_BEFORE, (AFUNPTR)docount, IARG_PTR, &(routinesMap[RTN_Name(rtn)]->instCount), IARG_END);
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

/* ===================================================================== */

bool cmp(const pair<ADDRINT, BranchData> &left, const pair<ADDRINT, BranchData> &right) {
    return left.second.totalIterNum > right.second.totalIterNum;
}

/* ===================================================================== */

VOID Fini(INT32 code, VOID *v) {
    fstream fd_out;
    fd_out.open("loop-count.csv", ios::out);
    map<ADDRINT, BranchData>::iterator it1 = branchMap.begin();
    map<string, RoutineCount *>::iterator it2;
    vector<pair<ADDRINT, BranchData> > currVector(branchMap.size());

    while (it1 != branchMap.end()) {
        if (!it1->second.counterLoopInvoked) {
            it1->second.counterLoopInvoked++;
        }
        UINT64 temp = it1->second.counterLoopInvoked;
        it1->second.meanTaken = (it1->second.totalIterNum) / (float)temp;
        it2 = routinesMap.find(it1->second.routineName);
        it1->second.routineCounter = it2->second->currRoutineCount;
        it1++;
    }

    copy(branchMap.begin(), branchMap.end(), currVector.begin());
    sort(currVector.begin(), currVector.end(), cmp);
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
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char *argv[]) {
    if (PIN_Init(argc, argv)) {
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
