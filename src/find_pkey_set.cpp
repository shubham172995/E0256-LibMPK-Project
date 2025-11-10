// Compile: g++ -std=c++11 find_pkey.cpp -I$PREFIX/include -L$PREFIX/lib -ldyninstAPI -linstructionAPI -lparseAPI -lsymtabAPI -ldw -ldwfl -o find_pkey
// Adjust link flags to match your installed dyninst libs (PREFIX==/data4/home/..../opt)

//  g++ -std=c++11 find_pkey_set.cpp   -I"$PREFIX/include" -I"$PREFIX/include/dyninstAPI"   -L"$PREFIX/lib"   -ldyninstAPI -linstructionAPI -lparseAPI -lsymtabAPI -ldw -ldwfl   -o find_pkey
// This program detects if the binary imports or defines 'pkey_set' (or other pkey_* symbols)

#include <iostream>
#include <vector>
#include <string>

#include <BPatch.h>
#include <BPatch_binaryEdit.h>
#include <BPatch_image.h>
#include <BPatch_function.h>
#include <BPatch_module.h>

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
        handle = bpatch.openBinary(name);
        break;
    }
    return handle;
}

void CreateAndInsertSnippet(BPatch_addressSpace *app, std::vector<BPatch_point *> *points) 
{
    BPatch_image *appImage = app->getImage();
    BPatch_variableExpr *intCounter = app->malloc(*(appImage->findType("int")));
    BPatch_arithExpr addOne(BPatch_assign, *intCounter, BPatch_arithExpr(BPatch_plus, *intCounter, BPatch_constExpr(1)));
    app->insertSnippet(addOne, *points);
}

std::vector<BPatch_point *> *FindEntryPoint(BPatch_addressSpace *app, std::vector<BPatch_function *> &functions, bool &foundFn) 
{
    BPatch_image *appImage = app->getImage();
    if (!appImage) 
    {
        std::cerr << "Failed to get image\n";
        return 3;
    }

    std::vector<BPatch_point *> *points;
    foundFn = appImage->findFunction("pkey_set", functions);
    points = functions[0]->findPoint(BPatch_entry);
    
    if (foundFn && !functions.empty()) 
    {
        std::cout << "appImage->findFunction: found " << functions.size() << " function(s) named 'pkey_set'.\n";
        points = functions[0]->findPoint(BPatch_entry);
        for (auto *f : functions) 
        {
            if (f && f->getName())
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


int main(int argc, char **argv) 
{
    if (argc != 4) 
    {
        std::cerr << "Usage: " << argv[0]
                << " <binary>"
                << " <mode: 0=create, 1=attach, 2=open>"
                << " <pid: -1 if not attaching>\n";
        return 1;
    }

    const char *bin = argv[1];
    const char *progName = "InstrumentedBinary";

    int mode = std::stoi(argv[2]);
    int pid = std::stoi(argv[3]);   //  Unless user wants to instrument running process, user gives -1.
    BPatch bpatch; 
    const char *progArgv[] = {argv[1], "-h", NULL};
    BPatch_addressSpace *app = StartInstrumenting(argv[2], bin, pid, progArgv);

    /*
    BPatch_binaryEdit *app = bpatch.openBinary(bin, true);
    if (!app) 
    {
        std::cerr << "Failed to open binary: " << bin << "\n";
        return 2;
    }
    */

    // find by function name (covers PLT-resolved functions and defined functions)
    // Procedure Linkage Table (PLT) and Global Offset Table (GOT) to find and call functions from shared libraries, a process called lazy binding
    std::vector<BPatch_function*> functions;
    bool foundFn = false;
    std::vector<BPatch_point *> *points = FindEntryPoint(app, functions, foundFn);

    if(foundFn)
    {
        CreateAndInsertSnippet(app, points);
    }

    FinishInstrumenting(app, progName);

    std::cout << "Done.\n";
    return 0;
}
