// Compile: g++ -std=c++11 find_pkey.cpp -I$PREFIX/include -L$PREFIX/lib -ldyninstAPI -linstructionAPI -lparseAPI -lsymtabAPI -ldw -ldwfl -o find_pkey
// Adjust link flags to match your installed dyninst libs (PREFIX==/data4/home/..../opt)

//  export PREFIX=/data4/home/shubhamshar1/opt

/*
    g++ -std=c++11 find_pkey_set.cpp \
  -I"$PREFIX/include" \
  -I"$PREFIX/include/dyninstAPI" \
  -L"$PREFIX/lib" \
  -Wl,-rpath,$PREFIX/lib \
  -ldyninstAPI -linstructionAPI -lparseAPI -lsymtabAPI \
  -o find_pkey
*/

// This program detects if the binary imports or defines 'pkey_set@plt' (or other pkey_* symbols)


#include <iostream>
#include <vector>
#include <string>

#include <Instruction.h>

#include <BPatch.h>
#include <BPatch_binaryEdit.h>
#include <BPatch_image.h>
#include <BPatch_function.h>
#include <BPatch_module.h>
#include <BPatch_point.h>
#include <BPatch_flowGraph.h>
#include <BPatch_basicBlock.h>

BPatch bpatch;

typedef enum 
{
    create,
    attach,
    open 
} accessType_t;



BPatch_addressSpace *StartInstrumenting(accessType_t accessType, const char *name, 
                                        int pid, // For attach 
                                        const char *argv[]) 
{ // For create
    BPatch_addressSpace *handle = NULL;
    switch (accessType) 
    {
    case create:
        handle = bpatch.processCreate(name, argv);
        break;
    case attach:
        handle = bpatch.processAttach(name, pid);
        break;
    case open:
        handle = bpatch.openBinary(name, true);
        break;
    }
    return handle;
}

/*
void CreateAndInsertSnippet(BPatch_addressSpace *app, std::vector<BPatch_point *> *points) 
{
    BPatch_image *appImage = app->getImage();
    BPatch_variableExpr *intCounter = app->malloc(*(appImage->findType("int")));
    BPatch_arithExpr addOne(BPatch_assign, *intCounter, BPatch_arithExpr(BPatch_plus, *intCounter, BPatch_constExpr(1)));
    app->insertSnippet(addOne, *points);
}
*/

std::vector<BPatch_point *> *FindEntryPoint(BPatch_addressSpace *app, std::vector<BPatch_function *> &functions, bool &foundFn) 
{
    if(!app)
    {
        return nullptr;
    }
    BPatch_image *appImage = app->getImage();
    if (!appImage) 
    {
        std::cerr << "Failed to get image\n";
        return nullptr;
    }

    std::vector<BPatch_point *> *points;
    foundFn = appImage->findFunction("pkey_set@plt", functions);
    
    if (foundFn && !functions.empty()) 
    {
        std::cout << "appImage->findFunction: found " << functions.size() << " function(s) named 'pkey_set@plt'.\n";
        points = functions[0]->findPoint(BPatch_entry);
        for (auto *f : functions) 
        {
            if (f && !f->getName().empty())
                std::cout << "  - " << f->getName() << "\n";
        }
    } 
    else 
    {
        std::cout << "appImage->findFunction: no function named 'pkey_set@plt' found.\n";
    }

    return points;
}

void FinishInstrumenting(BPatch_addressSpace *app, const char *newName) 
{
    if(!app)
    {
        return;
    }

    BPatch_process *appProc = dynamic_cast<BPatch_process *>(app);  //  bpatch.createProcess(...) or bpatch.attachProcess(...) returns a BPatch_process — a live process instrumentation handle.
    BPatch_binaryEdit *appBin = dynamic_cast<BPatch_binaryEdit *>(app); //  bpatch.openBinary(name) returns a pointer to a BPatch_binaryEdit object — this represents a static binary editing target (not a running process).
    if (appProc) 
    {
        appProc->continueExecution();
        while (!appProc->isTerminated()) 
        {
            bpatch.waitForStatusChange();
        }
    }
    if (appBin) 
    {
        appBin->writeFile(newName);
    }
}

int binaryAnalysis(BPatch_addressSpace *app) 
{
    BPatch_image *appImage = app->getImage();
    int insns_access_memory = 0;
    std::vector<BPatch_function *> functions;
    bool foundFn = appImage->findFunction("pkey_set@plt", functions);

    if(!foundFn || functions.empty())
    {
        return 0;
    }

    BPatch_flowGraph *fg = functions[0]->getCFG();
    if (!fg)
    {
        return 0;
    }

    std::set<BPatch_basicBlock *> blocks;
    fg->getAllBasicBlocks(blocks);
    for (auto *block : blocks)
    {
        std::vector<Dyninst::InstructionAPI::Instruction> insns;
        block->getInstructions(insns);

        for (auto &insn : insns)
        {
            if (insn.readsMemory() || insn.writesMemory()) 
            {
                insns_access_memory++;
            }
        }
    }

    return insns_access_memory;
}

void InstrumentMemory(BPatch_addressSpace *app, const char* libTrustedPath) 
{
    if(!app)
    {
        return;
    }

    app->loadLibrary(libTrustedPath);

    BPatch_image *appImage = app->getImage();
    if (!appImage) 
    {
        std::cerr << "Failed to get image\n";
        return;
    }

    std::vector<BPatch_function *> originalFunctions;
    bool foundOrig = appImage->findFunction("pkey_set@plt", originalFunctions);

    if(!foundOrig || originalFunctions.empty())
    {
        std::cerr << "pkey_set@plt not found\n";
        return;
    }

    std::vector<BPatch_function*> replacetemntFunctions;
    bool foundRepl = appImage->findFunction("my_pkey_set", replacetemntFunctions);

    if (!foundRepl || replacetemntFunctions.empty()) 
    {
        std::cerr << "my_pkey_set not found in image\n";
        return;
    }

    app->replaceFunction(*originalFunctions[0], *replacetemntFunctions[0]);
}


int main(int argc, char **argv) 
{
    if (argc != 5) 
    {
        std::cerr << "Usage: " << argv[0]
                << " <binary>"
                << " <mode: 0=create, 1=attach, 2=open>"
                << " <pid: -1 if not attaching>"
                << " lib_trusted.so complete path\n";
        return 1;
    }

    const char *bin = argv[1];
    const char *progName = "InstrumentedBinary";

    int mode = std::stoi(argv[2]);
    int pid = std::stoi(argv[3]);   //  Unless user wants to instrument running process, user gives -1.

    const char *progArgv[] = {argv[1], "-h", NULL};
    BPatch_addressSpace *app = StartInstrumenting(static_cast<accessType_t>(mode), bin, pid, progArgv);

    // find by function name (covers PLT-resolved functions and defined functions)
    // Procedure Linkage Table (PLT) and Global Offset Table (GOT) to find and call functions from shared libraries, a process called lazy binding
    std::vector<BPatch_function*> functions;
    bool foundFn = false;
    std::vector<BPatch_point *> *points = FindEntryPoint(app, functions, foundFn);

    InstrumentMemory(app, argv[4]);

    int insnsAccessMemory = 0;
    if(foundFn && !functions.empty())
    {
        //  For my current purpose, to redirect pkey_set@plt from untrusted to my_pkey_sey, I don't need this. But, adding for completeness and if needed in the future.
        insnsAccessMemory = binaryAnalysis(app);
    }

    std::cout << "insnsAccessMemory = " << insnsAccessMemory << "\n";

    FinishInstrumenting(app, progName);

    std::cout << "Done.\n";
    return 0;
}
