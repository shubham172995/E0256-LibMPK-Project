// find_pkey_set_fixed.cpp
// Compile with Dyninst headers/libs as in your environment.
// Usage:
//   ./find_pkey <binary> <mode: 0=create,1=attach,2=open> <pid or -1> <path-to-libtrusted.so>

#include <iostream>
#include <sstream>
#include <vector>
#include <string>
#include <set>
#include <cstdlib>

#include <Instruction.h>

#include <BPatch.h>
#include <BPatch_binaryEdit.h>
#include <BPatch_image.h>
#include <BPatch_function.h>
#include <BPatch_module.h>
#include <BPatch_point.h>
#include <BPatch_flowGraph.h>
#include <BPatch_basicBlock.h>
#include <BPatch_snippet.h>
#include <BPatch_process.h>

BPatch bpatch;

typedef enum {
    create,
    attach,
    open
} accessType_t;

BPatch_addressSpace *StartInstrumenting(accessType_t accessType, const char *name,
                                        int pid, const char *argv[])
{
    BPatch_addressSpace *handle = nullptr;
    switch (accessType) {
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

std::vector<BPatch_point *> *FindEntryPoint(BPatch_addressSpace *app, std::vector<BPatch_function *> &functions, bool &foundFn)
{
    if (!app) return nullptr;
    BPatch_image *appImage = app->getImage();
    if (!appImage) {
        std::cerr << "Failed to get image\n";
        return nullptr;
    }

    std::vector<BPatch_point *> *points = nullptr;
    foundFn = appImage->findFunction("pkey_set", functions);

    if (foundFn && !functions.empty()) {
        std::cout << "appImage->findFunction: found " << functions.size() << " function(s) named 'pkey_set'.\n";
        points = functions[0]->findPoint(BPatch_entry);
        for (auto *f : functions) {
            if (f) {
                try {
                    std::string nm = f->getName();
                    if (!nm.empty()) std::cout << "  - " << nm << "\n";
                } catch (...) {
                    // some versions may have different getName signatures
                }
            }
        }
    } else {
        std::cout << "appImage->findFunction: no function named 'pkey_set' found.\n";
    }

    return points;
}

void FinishInstrumenting(BPatch_addressSpace *app, const char *newName)
{
    if (!app) return;

    BPatch_process *appProc = dynamic_cast<BPatch_process *>(app);
    BPatch_binaryEdit *appBin = dynamic_cast<BPatch_binaryEdit *>(app);

    if (appProc) {
        appProc->continueExecution();
        while (!appProc->isTerminated()) {
            bpatch.waitForStatusChange();
        }
    }

    if (appBin) {
        // Only attempt writeFile if DYNINSTAPI_RT_LIB is defined (prevents assertion crash)
        const char *rt = std::getenv("DYNINSTAPI_RT_LIB");
        if (rt && rt[0]) {
            std::cerr << "Writing patched binary to: " << newName << "\n";
            appBin->writeFile(newName);
        } else {
            std::cerr << "Skipping writeFile(): DYNINSTAPI_RT_LIB not set (to avoid assertion). "
                      << "Set DYNINSTAPI_RT_LIB to use binary-edit writeFile().\n";
        }
    }
}

// Count memory-accessing instructions in pkey_set function (if present)
int binaryAnalysis(BPatch_addressSpace *app)
{
    if (!app) return 0;
    BPatch_image *appImage = app->getImage();
    if (!appImage) return 0;

    std::vector<BPatch_function *> functions;
    bool foundFn = appImage->findFunction("pkey_set", functions);
    if (!foundFn || functions.empty()) return 0;

    BPatch_flowGraph *fg = functions[0]->getCFG();
    if (!fg) return 0;

    int insns_access_memory = 0;
    std::set<BPatch_basicBlock *> blocks;
    fg->getAllBasicBlocks(blocks);

    for (auto *block : blocks) {
        if (!block) continue;
        std::vector<Dyninst::InstructionAPI::Instruction> insns;
        block->getInstructions(insns); // fills vector of shared_ptr
        for (auto &insn : insns) {
            try {
                if (insn.readsMemory() || insn.writesMemory()) {
                    insns_access_memory++;
                }
            } catch (...) {
                // fallback: ignore instruction if API mismatch
            }
        }
    }

    return insns_access_memory;
}

// Instrument/replace pkey_set calls: try module-local find first, else fallback to scanning callsites
void InstrumentMemory(BPatch_addressSpace *app, const char* libTrustedPath)
{
    if (!app) return;

    // 1) load replacement lib into image/process
    bool loaded = false;
    if (libTrustedPath && libTrustedPath[0]) {
        loaded = app->loadLibrary(libTrustedPath);
        std::cerr << "loadLibrary(" << libTrustedPath << ") returned " << loaded << "\n";
    } else {
        std::cerr << "No lib path provided to loadLibrary()\n";
    }

    BPatch_image *appImage = app->getImage();
    if (!appImage) {
        std::cerr << "Failed to get image\n";
        return;
    }

    // print modules
    std::vector<BPatch_module*> mods;
    appImage->getModules(mods);
    std::cerr << "Modules found: " << mods.size() << "\n";
    for (auto *m : mods) {
        if (!m) continue;
        std::cerr << "  module: " << m->getName() << "\n";
    }

    // find replacement symbol
    std::vector<BPatch_function*> replFuncs;
    bool foundRepl = appImage->findFunction("my_pkey_set", replFuncs);
    if (!foundRepl || replFuncs.empty()) {
        std::cerr << "my_pkey_set not found in image. Check loadLibrary or linking.\n";
        // we continue: fallback scanning might still insert a wrapper snippet
    } else {
        std::cerr << "Found my_pkey_set (replacement) in image\n";
    }

    // try to find module-local PLT / import stubs named "pkey_set"
    std::vector<BPatch_function*> origCandidates;
    for (auto *m : mods) {
        if (!m) continue;
        std::vector<BPatch_function*> modFuncs;
        bool ok = m->findFunction("pkey_set", modFuncs);
        if (ok && !modFuncs.empty()) {
            std::cerr << "Module " << m->getName() << " exposes pkey_set (count=" << modFuncs.size() << ")\n";
            for (auto *f : modFuncs) {
                if (f) {
                    try {
                        std::string nm = f->getName();
                        std::cerr << "   -> function: " << nm << " module=" << f->getModule()->getName() << "\n";
                    } catch (...) {}
                    origCandidates.push_back(f);
                }
            }
        }
    }

    // If we found candidate orig functions (e.g., pkey_set@plt), replace them
    if (!origCandidates.empty() && !replFuncs.empty()) {
        for (auto *orig : origCandidates) {
            if (!orig) continue;
            std::cerr << "Replacing orig function in module " << orig->getModule()->getName() << "\n";
            app->replaceFunction(*orig, *replFuncs[0]);
        }
        std::cerr << "Replacement done for modules exposing pkey_set\n";
        return;
    }

    // FALLBACK: scan call instructions in all functions and instrument those that call pkey_set
    std::cerr << "FALLBACK: scanning call instructions (old Dyninst API)\n";

    std::vector<BPatch_function*> allFuncs;
    appImage->getProcedures(allFuncs);

    for (auto *f : allFuncs) {
        if (!f) continue;

        // get instruction-level points (old API: BPatch_locInstruction)
        std::vector<BPatch_point*> *pts = f->findPoint(BPatch_locInstruction);
        if (!pts) continue;

        for (auto *p : *pts) {
            if (!p) continue;

            // old API: getCalledFunction (single)
            BPatch_function *callee = nullptr;
            try {
                callee = p->getCalledFunction();
            } catch (...) {
                callee = nullptr;
            }
            if (!callee) continue;

            // get callee name
            std::string nm;
            try { nm = callee->getName(); } catch (...) { nm = ""; }
            if (nm.find("pkey_set") != std::string::npos) {
                std::string parentName;
                try { parentName = f->getName(); } catch (...) { parentName = "<unknown>"; }

                std::cerr << "Found call to '" << nm << "' inside function '" << parentName << "' — inserting wrapper\n";

                if (!replFuncs.empty()) {
                    // create BPatch_funcCallExpr with empty args (old API)
                    std::vector<BPatch_snippet*> emptyArgs;
                    BPatch_funcCallExpr callRepl(*replFuncs[0], emptyArgs);
                    // insert before original call
                    app->insertSnippet(callRepl, *p, BPatch_callBefore);

                    // NOTE: insertSnippet(callBefore) does not stop the original call.
                    // To *prevent* original call you must patch the instruction bytes (advanced),
                    // or use other control-flow edits; not done here automatically.
                } else {
                    std::cerr << "No replacement function available; skipping instrumentation for this call\n";
                }
            }
        }
    }

    std::cerr << "Fallback scanning complete\n";
}

int main(int argc, char **argv)
{
    if (argc != 5) {
        std::cerr << "Usage: " << argv[0]
                  << " <binary> <mode: 0=create,1=attach,2=open> <pid|-1> <lib_trusted.so absolute path>\n";
        return 1;
    }

    const char *bin = argv[1];
    int mode = std::stoi(argv[2]);
    int pid = std::stoi(argv[3]);
    const char *libTrusted = argv[4];

    const char *progArgv[] = { bin, "-h", nullptr };
    BPatch_addressSpace *app = StartInstrumenting(static_cast<accessType_t>(mode), bin, pid, progArgv);
    if (!app) {
        std::cerr << "Failed to obtain BPatch_addressSpace for target '" << bin << "'\n";
        return 2;
    }

    std::vector<BPatch_function*> functions;
    bool foundFn = false;
    std::vector<BPatch_point*> *points = FindEntryPoint(app, functions, foundFn);

    InstrumentMemory(app, libTrusted);

    int insnsAccessMemory = 0;
    if (foundFn && !functions.empty()) {
        insnsAccessMemory = binaryAnalysis(app);
    }
    std::cout << "insnsAccessMemory = " << insnsAccessMemory << "\n";

    // If binary-edit, FinishInstrumenting attempts to write only if DYNINSTAPI_RT_LIB set.
    FinishInstrumenting(app, "a.out.patched");

    std::cout << "Done.\n";
    return 0;
}
