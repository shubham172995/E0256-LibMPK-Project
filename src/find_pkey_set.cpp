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

/*
    ./find_pkey E0256-LibMPK-Project/main 2 -1 /data4/home/shubhamshar1/e0256/E0256-LibMPK-Project/libtrusted.so
*/
// This program detects if the binary imports or defines 'pkey_set' (or other pkey_* symbols)


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
    foundFn = appImage->findFunction("pkey_set", functions);
    
    if (foundFn && !functions.empty()) 
    {
        std::cout << "appImage->findFunction: found " << functions.size() << " function(s) named 'pkey_set'.\n";
        points = functions[0]->findPoint(BPatch_entry);
        for (auto *f : functions) 
        {
            if (f && !f->getName().empty())
                std::cout << "  - " << f->getName() << "\n";
        }
    } 
    else 
    {
        std::cout << "appImage->findFunction: no function named 'pkey_set' found.\n";
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
    bool foundFn = appImage->findFunction("pkey_set", functions);

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
    if (!app) return;

    // 1) Try to load replacement library into image/process
    bool loaded = false;
    if (libTrustedPath && libTrustedPath[0]) 
    {
        loaded = app->loadLibrary(libTrustedPath);
        std::cerr << "loadLibrary(" << libTrustedPath << ") returned " << loaded << "\n";
    } 
    else 
    {
        std::cerr << "No lib path provided to loadLibrary()\n";
    }

    BPatch_image *appImage = app->getImage();
    if (!appImage) 
    {
        std::cerr << "Failed to get image\n";
        return;
    }

    // 2) Print modules for debugging
    std::vector<BPatch_module*> mods;
    appImage->getModules(mods);
    std::cerr << "Modules found: " << mods.size() << "\n";
    for (auto *m : mods) 
    {
        std::cerr << "  module: " << m->getName() << "\n";
    }

    // 3) Find replacement function (my_pkey_set) in the image
    std::vector<BPatch_function*> replFuncs;
    bool foundRepl = appImage->findFunction("my_pkey_set", replFuncs);
    if (!foundRepl || replFuncs.empty()) 
    {
        std::cerr << "my_pkey_set not found in image. Check loadLibrary or linking.\n";
        // don't return yet — you might want to scan callsites and insert snippet-based wrapper instead
        // return;
    } 
    else 
    {
        std::cerr << "Found my_pkey_set, address hint available\n";
    }

    // 4) Try to collect per-module orig functions (PLT/import stubs)
    std::vector<BPatch_function*> origCandidates;
    for (auto *m : mods) 
    {
        std::vector<BPatch_function*> modFuncs;
        bool ok = m->findFunction("pkey_set", modFuncs);
        if (ok && !modFuncs.empty()) 
        {
            std::cerr << "Module " << m->getName() << " exposes pkey_set (found " << modFuncs.size() << ")\n";
            for (auto *f : modFuncs) {
                if (f) {
                    std::cerr << "   -> function: " << f->getName() << " module=" << f->getModule()->getName() << "\n";
                    origCandidates.push_back(f);
                }
            }
        }
    }

    // 5) If we found candidate orig functions, replace them
    if (!origCandidates.empty() && !replFuncs.empty()) 
    {
        for (auto *orig : origCandidates) 
        {
            std::cerr << "Replacing orig function from module " << orig->getModule()->getName() << "\n";
            app->replaceFunction(*orig, *replFuncs[0]);
        }
        std::cerr << "Replacement done for modules exposing pkey_set\n";
        return;
    }

    // 6) FALLBACK: scan callsites in modules and instrument call instructions that target pkey_set@plt
    // This is slower but works even when pkey_set has no visible symbol in the module.
    std::cerr << "FALLBACK: scanning call instructions in modules to locate pkey_set callsites\n";

    // iterate functions in image
    std::vector<BPatch_function*> allFuncs;
    appImage->getProcedures(allFuncs); // getProcedures gives all functions/procedures
    for (auto *f : allFuncs) 
    {
        if (!f) 
            continue;
        // get call points inside this function
        std::vector<BPatch_point*> *callPoints = f->findPoint(BPatch_callInstruction);
        if (!callPoints) continue;
        for (auto *p : *callPoints) 
        {
            // getCalledFunctions is a convenience to see resolved callee BPatch_function*
            BPatch_function *callees[4];
            int nc = p->getCalledFunctions(callees, 4);
            if (nc <= 0) continue;
            for (int i = 0; i < nc; ++i) 
            {
                BPatch_function *callee = callees[i];
                if (!callee) continue;
                std::string nm = callee->getName();
                if (nm.find("pkey_set") != std::string::npos) 
                {
                    std::cerr << "Found call to " << nm << " in function " << f->getName() << " — instrumenting\n";
                    if (!replFuncs.empty()) 
                    {
                        // Insert a call to replacement BEFORE the original call and optionally skip original:
                        app->insertSnippet(BPatch_funcCallExpr(*replFuncs[0]), *p, BPatch_callBefore);
                        // If you want to avoid executing original, you must also modify the original call to be a NOP or return early.
                        // That's advanced: consider replacing the instruction bytes or using an entry snippet that returns early.
                    } 
                    else 
                    {
                        std::cerr << "No replacement function available; skipping instrumentation\n";
                    }
                }
            }
        }
    }

    std::cerr << "Fallback scanning complete\n";
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
        //  For my current purpose, to redirect pkey_set from untrusted to my_pkey_sey, I don't need this. But, adding for completeness and if needed in the future.
        insnsAccessMemory = binaryAnalysis(app);
    }

    std::cout << "insnsAccessMemory = " << insnsAccessMemory << "\n";

    FinishInstrumenting(app, progName);

    std::cout << "Done.\n";
    return 0;
}
