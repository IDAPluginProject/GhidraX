/**
 * decompiler_bind.cpp — pybind11 binding for the full Ghidra C++ decompiler
 *
 * Exposes a single high-level Python class `DecompilerNative` that:
 *   1. Initializes the decompiler library with spec file paths
 *   2. Accepts raw binary bytes + architecture info
 *   3. Decompiles a function at a given entry point
 *   4. Returns the C source code as a string
 *
 * Build as: decompiler_native.pyd
 */

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>

#include "libdecomp.hh"
#include "raw_arch.hh"
#include "sleigh_arch.hh"
#include "loadimage.hh"
#include "printc.hh"
#include "funcdata.hh"
#include "flow.hh"
#include "coreaction.hh"
#include "block.hh"
#include "varnode.hh"
#include "op.hh"

namespace py = pybind11;

using namespace ghidra;

// ---------------------------------------------------------------------------
// Custom LoadImage backed by a raw byte buffer (from Python)
// ---------------------------------------------------------------------------
class BufferImage : public LoadImage {
    const uint1 *buf_;
    int4 bufsize_;
    AddrSpace *spc_;
    uintb baseaddr_;
public:
    BufferImage(uintb baseaddr)
        : LoadImage("nofile"), buf_(nullptr), bufsize_(0), spc_(nullptr), baseaddr_(baseaddr) {}

    void setData(const uint1 *data, int4 sz) { buf_ = data; bufsize_ = sz; }
    void attachToSpace(AddrSpace *s) { spc_ = s; }

    void loadFill(uint1 *ptr, int4 size, const Address &addr) override {
        uintb off = addr.getOffset();
        if (off < baseaddr_ || buf_ == nullptr) {
            memset(ptr, 0, size);
            return;
        }
        uintb rel = off - baseaddr_;
        for (int4 i = 0; i < size; ++i) {
            if ((int4)(rel + i) < bufsize_)
                ptr[i] = buf_[rel + i];
            else
                ptr[i] = 0;
        }
    }

    string getArchType(void) const override { return "buffer"; }
    void adjustVma(long adjust) override {}
};

// ---------------------------------------------------------------------------
// Custom Architecture that uses our BufferImage
// ---------------------------------------------------------------------------
class BufferArchitecture : public SleighArchitecture {
    BufferImage *bufimg_;
    uintb baseaddr_;
public:
    BufferArchitecture(const string &slapath, const string &target,
                       uintb baseaddr, ostream *estream)
        : SleighArchitecture(slapath, target, estream),
          bufimg_(nullptr), baseaddr_(baseaddr) {}

    void setImageData(const uint1 *data, int4 sz) {
        if (bufimg_) bufimg_->setData(data, sz);
    }

protected:
    void buildLoader(DocumentStorage &store) override {
        collectSpecFiles(*errorstream);
        bufimg_ = new BufferImage(baseaddr_);
        loader = bufimg_;
    }

    void resolveArchitecture(void) override {
        archid = getTarget();
        SleighArchitecture::resolveArchitecture();
    }

    void postSpecFile(void) override {
        Architecture::postSpecFile();
        if (bufimg_)
            bufimg_->attachToSpace(getDefaultCodeSpace());
    }
};

// ---------------------------------------------------------------------------
// Main Python-facing class
// ---------------------------------------------------------------------------
class DecompilerNative {
    bool initialized_;
    vector<string> specpaths_;     // flat directories (direct addDir2Path)
    vector<string> ghidraroots_;   // Ghidra-layout roots (scanForSleighDirectories)
    ostringstream errstream_;

public:
    DecompilerNative() : initialized_(false) {}

    void addSpecPath(const string &path) {
        specpaths_.push_back(path);
    }

    void addGhidraRoot(const string &path) {
        ghidraroots_.push_back(path);
    }

    void initialize() {
        if (initialized_) return;
        // Initialize core decompiler subsystems
        AttributeId::initialize();
        ElementId::initialize();
        CapabilityPoint::initializeAll();
        ArchitectureCapability::sortCapabilities();

        // Scan Ghidra-layout directories (Ghidra/<proc>/data/languages/)
        for (const auto &root : ghidraroots_)
            SleighArchitecture::scanForSleighDirectories(root);

        // Add flat spec directories directly
        for (const auto &p : specpaths_)
            SleighArchitecture::specpaths.addDir2Path(p);

        initialized_ = true;
    }

    string decompile(const string &slapath,
                     const string &target,
                     const py::bytes &image,
                     uintb baseaddr,
                     uintb entry,
                     int4 funcsize) {
        try {
            if (!initialized_) initialize();
        } catch (LowlevelError &e) {
            throw std::runtime_error(string("Init error: ") + e.explain);
        } catch (std::exception &e) {
            throw std::runtime_error(string("Init error: ") + e.what());
        }

        errstream_.str("");
        errstream_.clear();

        // Get raw bytes from Python
        string imgstr = image;
        const uint1 *imgdata = (const uint1 *)imgstr.data();
        int4 imgsize = (int4)imgstr.size();

        // Build architecture
        try {
            BufferArchitecture arch(slapath, target, baseaddr, &errstream_);
            DocumentStorage store;
            arch.init(store);
            arch.setImageData(imgdata, imgsize);

            // Create the action group and set it as current
            arch.allacts.universalAction(&arch);
            arch.allacts.resetDefaults();

            // Find or create the function
            Address funcEntry(arch.getDefaultCodeSpace(), entry);
            Funcdata *fd = arch.symboltab->getGlobalScope()->findFunction(funcEntry);
            if (fd == nullptr) {
                string funcname = "func_" + to_string(entry);
                arch.symboltab->getGlobalScope()->addFunction(funcEntry, funcname);
                fd = arch.symboltab->getGlobalScope()->findFunction(funcEntry);
                if (fd == nullptr) {
                    throw std::runtime_error("Could not create function at 0x" + to_string(entry));
                }
            }

            // Run the decompiler action pipeline
            Action *act = arch.allacts.getCurrent();
            if (act == nullptr) {
                throw std::runtime_error("No current action set");
            }
            act->reset(*fd);
            int4 res = act->perform(*fd);
            if (res < 0) {
                throw std::runtime_error("Decompilation incomplete (breakpoint)");
            }

            // Print the result
            ostringstream codestream;
            arch.print->setOutputStream(&codestream);
            arch.print->docFunction(fd);

            return codestream.str();
        } catch (LowlevelError &e) {
            throw std::runtime_error(string("Decompiler error: ") + e.explain +
                                     "\nInternal log: " + errstream_.str());
        } catch (DecoderError &e) {
            throw std::runtime_error(string("Decoder error: ") + e.explain +
                                     "\nInternal log: " + errstream_.str());
        } catch (std::runtime_error &) {
            throw;  // re-throw our own runtime_errors
        } catch (std::exception &e) {
            throw std::runtime_error(string("C++ exception: ") + e.what() +
                                     "\nInternal log: " + errstream_.str());
        } catch (...) {
            throw std::runtime_error(string("Unknown C++ exception") +
                                     "\nInternal log: " + errstream_.str());
        }
    }

    string getErrors() const {
        return errstream_.str();
    }

    // -----------------------------------------------------------------
    // Bridge A: Staged decompilation with IR snapshot export
    // -----------------------------------------------------------------

    /// Dump a single Varnode as a Python dict
    static py::dict dumpVarnode(const Varnode *vn) {
        py::dict d;
        d["space"] = vn->getSpace()->getName();
        d["offset"] = (uint64_t)vn->getOffset();
        d["size"] = (int)vn->getSize();
        d["flags"] = (uint32_t)vn->getFlags();
        d["is_input"] = vn->isInput();
        d["is_free"] = vn->isFree();
        d["is_constant"] = vn->isConstant();
        d["is_written"] = vn->isWritten();
        return d;
    }

    /// Dump a single PcodeOp as a Python dict
    static py::dict dumpOp(const PcodeOp *op) {
        py::dict d;
        d["opcode"] = (int)op->code();
        d["addr"] = (uint64_t)op->getAddr().getOffset();
        d["seq_order"] = (int)op->getSeqNum().getOrder();
        d["seq_time"] = (uint64_t)op->getSeqNum().getTime();

        // Output varnode
        const Varnode *out = op->getOut();
        if (out != nullptr)
            d["output"] = dumpVarnode(out);
        else
            d["output"] = py::none();

        // Input varnodes
        py::list inputs;
        for (int4 k = 0; k < op->numInput(); ++k)
            inputs.append(dumpVarnode(op->getIn(k)));
        d["inputs"] = inputs;

        return d;
    }

    /// Dump the entire Funcdata IR state into a Python dict
    static py::dict dumpIr(const Funcdata *fd) {
        py::dict result;

        // --- Basic blocks ---
        py::list blocks;
        const BlockGraph &bblocks = fd->getBasicBlocks();
        for (int4 i = 0; i < bblocks.getSize(); ++i) {
            const FlowBlock *bl = bblocks.getBlock(i);
            py::dict bdict;
            bdict["index"] = bl->getIndex();
            bdict["start"] = (uint64_t)bl->getStart().getOffset();
            bdict["stop"] = (uint64_t)bl->getStop().getOffset();

            // Successor indices
            py::list succs;
            for (int4 j = 0; j < bl->sizeOut(); ++j)
                succs.append(bl->getOut(j)->getIndex());
            bdict["successors"] = succs;

            // Predecessor indices
            py::list preds;
            for (int4 j = 0; j < bl->sizeIn(); ++j)
                preds.append(bl->getIn(j)->getIndex());
            bdict["predecessors"] = preds;

            // Ops in block (only for t_basic)
            py::list ops;
            if (bl->getType() == FlowBlock::t_basic) {
                const BlockBasic *bbl = (const BlockBasic *)bl;
                for (auto it = bbl->beginOp(); it != bbl->endOp(); ++it) {
                    ops.append(dumpOp(*it));
                }
            }
            bdict["ops"] = ops;
            bdict["num_ops"] = (int)py::len(ops);

            blocks.append(bdict);
        }
        result["blocks"] = blocks;
        result["num_blocks"] = bblocks.getSize();

        // --- All alive PcodeOps (flat list) ---
        py::list all_ops;
        for (auto it = fd->beginOpAlive(); it != fd->endOpAlive(); ++it)
            all_ops.append(dumpOp(*it));
        result["all_ops"] = all_ops;
        result["num_ops"] = (int)py::len(all_ops);

        return result;
    }

    /// Decompile to a specific stage and return IR snapshot.
    ///
    /// stop_after:
    ///   "flow"     — after flow analysis (basic blocks constructed)
    ///   "heritage" — after SSA construction (phi-nodes placed, vars renamed)
    ///   "full"     — full pipeline (also returns "c_code")
    py::dict decompile_staged(const string &slapath,
                              const string &target,
                              const py::bytes &image,
                              uintb baseaddr,
                              uintb entry,
                              int4 funcsize,
                              const string &stop_after) {
        try {
            if (!initialized_) initialize();
        } catch (LowlevelError &e) {
            throw std::runtime_error(string("Init error: ") + e.explain);
        } catch (std::exception &e) {
            throw std::runtime_error(string("Init error: ") + e.what());
        }

        errstream_.str("");
        errstream_.clear();

        string imgstr = image;
        const uint1 *imgdata = (const uint1 *)imgstr.data();
        int4 imgsize = (int4)imgstr.size();

        try {
            BufferArchitecture arch(slapath, target, baseaddr, &errstream_);
            DocumentStorage store;
            arch.init(store);
            arch.setImageData(imgdata, imgsize);

            arch.allacts.universalAction(&arch);
            arch.allacts.resetDefaults();

            Address funcEntry(arch.getDefaultCodeSpace(), entry);
            Funcdata *fd = arch.symboltab->getGlobalScope()->findFunction(funcEntry);
            if (fd == nullptr) {
                string funcname = "func_" + to_string(entry);
                arch.symboltab->getGlobalScope()->addFunction(funcEntry, funcname);
                fd = arch.symboltab->getGlobalScope()->findFunction(funcEntry);
                if (fd == nullptr)
                    throw std::runtime_error("Could not create function");
            }

            py::dict result;
            result["stage"] = stop_after;

            if (stop_after == "flow") {
                // Stage 1: flow analysis only
                fd->startProcessing();
                result["ir"] = dumpIr(fd);

            } else if (stop_after == "heritage") {
                // Stage 2: flow + heritage (SSA)
                // Must run prerequisite actions before opHeritage to avoid
                // segfault — heritage needs function prototypes, call specs,
                // varnode properties, etc. to be set up first.
                // This mirrors the universalAction order in coreaction.cc.
                AddrSpace *stackspace = arch.getStackSpace();

                ActionStart           a1("base");        a1.reset(*fd); a1.perform(*fd);
                ActionConstbase       a2("base");        a2.reset(*fd); a2.perform(*fd);
                ActionNormalizeSetup  a3("normalanalysis"); a3.reset(*fd); a3.perform(*fd);
                ActionDefaultParams   a4("base");        a4.reset(*fd); a4.perform(*fd);
                ActionExtraPopSetup   a5("base", stackspace); a5.reset(*fd); a5.perform(*fd);
                ActionPrototypeTypes  a6("protorecovery"); a6.reset(*fd); a6.perform(*fd);
                ActionFuncLink        a7("protorecovery"); a7.reset(*fd); a7.perform(*fd);
                ActionFuncLinkOutOnly a8("noproto");      a8.reset(*fd); a8.perform(*fd);
                ActionUnreachable     a9("base");        a9.reset(*fd); a9.perform(*fd);
                ActionVarnodeProps    a10("base");       a10.reset(*fd); a10.perform(*fd);

                fd->opHeritage();
                result["ir"] = dumpIr(fd);

            } else {
                // Stage "full": complete pipeline + C code
                Action *act = arch.allacts.getCurrent();
                if (act == nullptr)
                    throw std::runtime_error("No current action set");
                act->reset(*fd);
                act->perform(*fd);

                result["ir"] = dumpIr(fd);

                ostringstream codestream;
                arch.print->setOutputStream(&codestream);
                arch.print->docFunction(fd);
                result["c_code"] = codestream.str();
            }

            result["errors"] = errstream_.str();
            return result;

        } catch (LowlevelError &e) {
            throw std::runtime_error(string("Decompiler error: ") + e.explain +
                                     "\nInternal log: " + errstream_.str());
        } catch (DecoderError &e) {
            throw std::runtime_error(string("Decoder error: ") + e.explain +
                                     "\nInternal log: " + errstream_.str());
        } catch (std::runtime_error &) {
            throw;
        } catch (std::exception &e) {
            throw std::runtime_error(string("C++ exception: ") + e.what() +
                                     "\nInternal log: " + errstream_.str());
        } catch (...) {
            throw std::runtime_error(string("Unknown C++ exception") +
                                     "\nInternal log: " + errstream_.str());
        }
    }
};

// ---------------------------------------------------------------------------
// pybind11 module definition
// ---------------------------------------------------------------------------
PYBIND11_MODULE(decompiler_native, m) {
    m.doc() = "Native Ghidra decompiler engine (full C++ pipeline)";

    py::class_<DecompilerNative>(m, "DecompilerNative")
        .def(py::init<>())
        .def("add_spec_path", &DecompilerNative::addSpecPath,
             "Add a flat directory containing .ldefs/.pspec/.cspec files")
        .def("add_ghidra_root", &DecompilerNative::addGhidraRoot,
             "Add a Ghidra-layout root (scans <root>/Ghidra/*/data/languages/)")
        .def("initialize", &DecompilerNative::initialize,
             "Initialize the decompiler library")
        .def("decompile", &DecompilerNative::decompile,
             py::arg("sla_path"),
             py::arg("target"),
             py::arg("image"),
             py::arg("base_addr"),
             py::arg("entry"),
             py::arg("func_size") = 0,
             "Decompile a function from raw binary bytes.\n"
             "Returns C source code as a string.\n\n"
             "Args:\n"
             "  sla_path: Path to the .sla file\n"
             "  target: Language id (e.g. 'x86:LE:64:default')\n"
             "  image: Raw binary bytes\n"
             "  base_addr: Base address of the image\n"
             "  entry: Entry point address of the function\n"
             "  func_size: Size hint (0 = auto-detect)\n")
        .def("get_errors", &DecompilerNative::getErrors,
             "Get error messages from the last operation")
        .def("decompile_staged", &DecompilerNative::decompile_staged,
             py::arg("sla_path"),
             py::arg("target"),
             py::arg("image"),
             py::arg("base_addr"),
             py::arg("entry"),
             py::arg("func_size") = 0,
             py::arg("stop_after") = "full",
             "Decompile to a specific stage and return IR snapshot.\n\n"
             "stop_after: 'flow', 'heritage', or 'full'\n"
             "Returns a dict with 'stage', 'ir' (blocks/ops), and optionally 'c_code'.\n");
}
