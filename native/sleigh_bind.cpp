/* sleigh_bind.cpp - pybind11 binding for Ghidra SLEIGH engine
 *
 * Compiles into sleigh_native.pyd, exposing:
 *   - SleighNative class: load .sla, set binary image, disassemble, lift to pcode
 */

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/numpy.h>

#include "loadimage.hh"
#include "sleigh.hh"
#include "slaformat.hh"

#include <sstream>
#include <fstream>
#include <vector>
#include <tuple>
#include <cstring>

namespace py = pybind11;
using namespace ghidra;

// ========================================================================
// Internal LoadImage backed by a raw byte buffer
// ========================================================================
class BufferLoadImage : public LoadImage {
    std::vector<uint1> buf;
    uintb baseaddr;
public:
    BufferLoadImage() : LoadImage("nofile"), baseaddr(0) {}

    void setData(uintb base, const uint1* data, int4 len) {
        baseaddr = base;
        buf.assign(data, data + len);
    }

    virtual void loadFill(uint1* ptr, int4 size, const Address& addr) override {
        uintb start = addr.getOffset();
        for (int4 i = 0; i < size; ++i) {
            uintb cur = start + i;
            if (cur < baseaddr || cur >= baseaddr + (uintb)buf.size())
                ptr[i] = 0;
            else
                ptr[i] = buf[(int4)(cur - baseaddr)];
        }
    }
    virtual string getArchType(void) const override { return "buffer"; }
    virtual void adjustVma(long adjust) override { baseaddr += adjust; }
};

// ========================================================================
// Assembly capture
// ========================================================================
class AssemblyCapture : public AssemblyEmit {
public:
    string mnemonic;
    string body;
    virtual void dump(const Address&, const string& m, const string& b) override {
        mnemonic = m;
        body = b;
    }
};

// ========================================================================
// Pcode capture -> Python-friendly structs
// ========================================================================
struct PyVarnode {
    std::string space;
    uint64_t offset;
    uint32_t size;
};

struct PyPcodeOp {
    uint32_t opcode;
    uint64_t addr;
    PyVarnode output;
    bool has_output;
    std::vector<PyVarnode> inputs;
};

struct PyDisasmResult {
    uint64_t addr;
    int length;
    std::string mnemonic;
    std::string body;
};

struct PyPcodeResult {
    uint64_t addr;
    int length;
    std::string mnemonic;
    std::string body;
    std::vector<PyPcodeOp> ops;
};

class PcodeCapture : public PcodeEmit {
public:
    std::vector<PyPcodeOp>& ops;
    PcodeCapture(std::vector<PyPcodeOp>& o) : ops(o) {}

    virtual void dump(const Address& addr, OpCode opc,
                      VarnodeData* outvar, VarnodeData* vars, int4 isize) override {
        PyPcodeOp op;
        op.opcode = (uint32_t)opc;
        op.addr = addr.getOffset();
        if (outvar) {
            op.has_output = true;
            op.output.space = outvar->space->getName();
            op.output.offset = outvar->offset;
            op.output.size = outvar->size;
        } else {
            op.has_output = false;
        }
        for (int4 i = 0; i < isize; ++i) {
            PyVarnode vn;
            vn.space = vars[i].space->getName();
            vn.offset = vars[i].offset;
            vn.size = vars[i].size;
            op.inputs.push_back(vn);
        }
        ops.push_back(op);
    }
};

// ========================================================================
// Derived Sleigh that exposes protected decode()
// ========================================================================
namespace ghidra {
class SleighExposed : public Sleigh {
public:
    SleighExposed(LoadImage* ld, ContextDatabase* c_db) : Sleigh(ld, c_db) {}
    void decodeSla(Decoder& decoder) { decode(decoder); }
};
} // namespace ghidra
using ghidra::SleighExposed;

// ========================================================================
// Main wrapper class
// ========================================================================
class SleighNative {
    BufferLoadImage loader;
    ContextInternal context;
    SleighExposed* trans;
    bool initialized;

public:
    SleighNative() : trans(nullptr), initialized(false) {
        AttributeId::initialize();
        ElementId::initialize();
    }
    ~SleighNative() { delete trans; }

    void loadSla(const std::string& sla_path) {
        delete trans;
        trans = new SleighExposed(&loader, &context);

        // Build a tiny XML wrapper: <sleigh>/path/to/file.sla</sleigh>
        // Sleigh::initialize reads the .sla path from the XML tag content,
        // opens the file, parses it via FormatDecode, AND creates the
        // disassembly cache (discache) which is critical.
        std::string xmlContent = "<sleigh>" + sla_path + "</sleigh>";
        std::istringstream xmlStream(xmlContent);

        DocumentStorage store;
        Element* root = store.parseDocument(xmlStream)->getRoot();
        store.registerTag(root);
        trans->initialize(store);

        initialized = true;
    }

    void setContextDefault(const std::string& name, uint32_t value) {
        context.setVariableDefault(name, value);
    }

    void setImage(uint64_t base_addr, py::bytes data) {
        std::string s = data;
        loader.setData((uintb)base_addr, (const uint1*)s.data(), (int4)s.size());
    }

    // Get all register names
    py::dict getRegisters() {
        if (!initialized) throw std::runtime_error("Not initialized");
        py::dict result;
        map<VarnodeData, string> reglist;
        trans->getAllRegisters(reglist);
        for (auto& kv : reglist) {
            py::tuple info = py::make_tuple(
                kv.first.space->getName(),
                (uint64_t)kv.first.offset,
                (uint32_t)kv.first.size
            );
            result[py::str(kv.second)] = info;
        }
        return result;
    }

    // Disassemble one instruction
    PyDisasmResult disassemble(uint64_t addr) {
        if (!initialized) throw std::runtime_error("Not initialized");
        if (!trans) throw std::runtime_error("Translator is null");
        AddrSpace* spc = trans->getDefaultCodeSpace();
        if (!spc) throw std::runtime_error("No default code space");
        AssemblyCapture cap;
        Address a(spc, addr);
        int4 len = 0;
        try {
            len = trans->printAssembly(cap, a);
        } catch (BadDataError& e) {
            throw std::runtime_error(std::string("Bad data: ") + e.explain);
        } catch (UnimplError& e) {
            len = e.instruction_length;
            cap.mnemonic = "??";
            cap.body = e.explain;
        } catch (LowlevelError& e) {
            throw std::runtime_error(std::string("Lowlevel: ") + e.explain);
        } catch (std::exception& e) {
            throw std::runtime_error(std::string("Exception: ") + e.what());
        } catch (...) {
            throw std::runtime_error("Unknown crash in printAssembly");
        }
        return {addr, len, cap.mnemonic, cap.body};
    }

    // Disassemble a range
    std::vector<PyDisasmResult> disassembleRange(uint64_t start, uint64_t end) {
        if (!initialized) throw std::runtime_error("Not initialized");
        std::vector<PyDisasmResult> results;
        uint64_t cur = start;
        while (cur < end) {
            AssemblyCapture cap;
            Address a(trans->getDefaultCodeSpace(), cur);
            int4 len;
            try {
                len = trans->printAssembly(cap, a);
            } catch (...) {
                break;
            }
            if (len <= 0) break;
            results.push_back({cur, len, cap.mnemonic, cap.body});
            cur += len;
        }
        return results;
    }

    // Translate one instruction to pcode
    PyPcodeResult pcode(uint64_t addr) {
        if (!initialized) throw std::runtime_error("Not initialized");
        PyPcodeResult result;
        result.addr = addr;

        // Get assembly
        AssemblyCapture acap;
        Address a(trans->getDefaultCodeSpace(), addr);
        trans->printAssembly(acap, a);
        result.mnemonic = acap.mnemonic;
        result.body = acap.body;

        // Get pcode
        PcodeCapture pcap(result.ops);
        result.length = trans->oneInstruction(pcap, a);
        return result;
    }

    // Translate a range of instructions to pcode
    std::vector<PyPcodeResult> pcodeRange(uint64_t start, uint64_t end) {
        if (!initialized) throw std::runtime_error("Not initialized");
        std::vector<PyPcodeResult> results;
        uint64_t cur = start;
        while (cur < end) {
            try {
                auto r = pcode(cur);
                if (r.length <= 0) break;
                cur += r.length;
                results.push_back(std::move(r));
            } catch (...) {
                break;
            }
        }
        return results;
    }

    std::string getDefaultCodeSpaceName() {
        if (!initialized) throw std::runtime_error("Not initialized");
        return trans->getDefaultCodeSpace()->getName();
    }

    std::string getRegisterName(const std::string& space, uint64_t offset, int size) {
        if (!initialized) throw std::runtime_error("Not initialized");
        AddrSpace* spc = trans->getSpaceByName(space);
        if (!spc) return "";
        return trans->getRegisterName(spc, offset, size);
    }

    bool isInitialized() const { return initialized; }
};

// ========================================================================
// pybind11 module definition
// ========================================================================
PYBIND11_MODULE(sleigh_native, m) {
    m.doc() = "Native SLEIGH engine for instruction decoding and P-code lifting";

    py::class_<PyVarnode>(m, "Varnode")
        .def_readonly("space", &PyVarnode::space)
        .def_readonly("offset", &PyVarnode::offset)
        .def_readonly("size", &PyVarnode::size)
        .def("__repr__", [](const PyVarnode& v) {
            std::ostringstream ss;
            ss << "(" << v.space << ", 0x" << std::hex << v.offset << ", " << std::dec << v.size << ")";
            return ss.str();
        });

    py::class_<PyPcodeOp>(m, "PcodeOp")
        .def_readonly("opcode", &PyPcodeOp::opcode)
        .def_readonly("addr", &PyPcodeOp::addr)
        .def_readonly("output", &PyPcodeOp::output)
        .def_readonly("has_output", &PyPcodeOp::has_output)
        .def_readonly("inputs", &PyPcodeOp::inputs)
        .def("__repr__", [](const PyPcodeOp& op) {
            std::ostringstream ss;
            ss << "PcodeOp(opc=" << op.opcode << ", inputs=" << op.inputs.size() << ")";
            return ss.str();
        });

    py::class_<PyDisasmResult>(m, "DisasmResult")
        .def_readonly("addr", &PyDisasmResult::addr)
        .def_readonly("length", &PyDisasmResult::length)
        .def_readonly("mnemonic", &PyDisasmResult::mnemonic)
        .def_readonly("body", &PyDisasmResult::body)
        .def("__repr__", [](const PyDisasmResult& r) {
            std::ostringstream ss;
            ss << "0x" << std::hex << r.addr << ": " << r.mnemonic << " " << r.body;
            return ss.str();
        });

    py::class_<PyPcodeResult>(m, "PcodeResult")
        .def_readonly("addr", &PyPcodeResult::addr)
        .def_readonly("length", &PyPcodeResult::length)
        .def_readonly("mnemonic", &PyPcodeResult::mnemonic)
        .def_readonly("body", &PyPcodeResult::body)
        .def_readonly("ops", &PyPcodeResult::ops)
        .def("__repr__", [](const PyPcodeResult& r) {
            std::ostringstream ss;
            ss << "0x" << std::hex << r.addr << ": " << r.mnemonic << " " << r.body
               << " (" << std::dec << r.ops.size() << " pcode ops)";
            return ss.str();
        });

    py::class_<SleighNative>(m, "SleighNative")
        .def(py::init<>())
        .def("load_sla", &SleighNative::loadSla, py::arg("sla_path"),
             "Load a compiled .sla specification file")
        .def("set_image", &SleighNative::setImage,
             py::arg("base_addr"), py::arg("data"),
             "Set the binary image bytes and base address")
        .def("set_context_default", &SleighNative::setContextDefault,
             py::arg("name"), py::arg("value"),
             "Set a default context variable (e.g. addrsize=1 for 32-bit x86)")
        .def("disassemble", &SleighNative::disassemble, py::arg("addr"),
             "Disassemble one instruction at the given address")
        .def("disassemble_range", &SleighNative::disassembleRange,
             py::arg("start"), py::arg("end"),
             "Disassemble all instructions in [start, end)")
        .def("pcode", &SleighNative::pcode, py::arg("addr"),
             "Translate one instruction to P-code at the given address")
        .def("pcode_range", &SleighNative::pcodeRange,
             py::arg("start"), py::arg("end"),
             "Translate all instructions in [start, end) to P-code")
        .def("get_registers", &SleighNative::getRegisters,
             "Get a dict of register name -> (space, offset, size)")
        .def("get_register_name", &SleighNative::getRegisterName,
             py::arg("space"), py::arg("offset"), py::arg("size"),
             "Look up a register name by its storage location")
        .def("get_default_code_space", &SleighNative::getDefaultCodeSpaceName,
             "Get the name of the default code address space")
        .def_property_readonly("initialized", &SleighNative::isInitialized);
}
