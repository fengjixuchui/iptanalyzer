// dllmain.cpp : Defines the entry point for the DLL application.

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include "ipt.h"
#include "intel-pt.h"

namespace py = pybind11;

PYBIND11_MODULE(pyipt, m) {
    py::class_<ipt>(m, "ipt")
        .def(py::init())
        .def("open", &ipt::Open)
        .def("get_sync_offset", &ipt::GetSyncOffset)
        .def("get_offset", &ipt::GetOffset)
        .def("get_size", &ipt::GetSize)
        .def("get_status", &ipt::GetStatus)
        .def("add_image", &ipt::AddImage)
        .def("decode_instruction", &ipt::DecodeInstruction)
        .def("decode_block", &ipt::DecodeBlock)
        .def("get_decode_status", &ipt::GetDecodeStatus)
        .def("get_current_cr3", &ipt::GetCurrentCR3);

    py::class_<pt_insn>(m, "pt_insn")
        .def_readwrite("ip", &pt_insn::ip)
        .def("GetRawBytes",
            [](const pt_insn& a) {
                vector<uint8_t> arr;

                for (int i = 0; i < 15; i++)
                {
                    arr.push_back(a.raw[i]);
                }
                return arr;
            }
         );

    py::class_<pt_block>(m, "pt_block")
        .def_readwrite("ip", &pt_block::ip)
        .def_readwrite("end_ip", &pt_block::end_ip)
        .def_readwrite("ninsn", &pt_block::ninsn)
        .def_readwrite("size", &pt_block::size);

    py::enum_<pt_error_code>(m, "pt_error_code")
        .value("pte_ok", pt_error_code::pte_ok)
        .value("pte_internal", pt_error_code::pte_internal)
        .value("pte_invalid", pt_error_code::pte_invalid)
        .value("pte_nosync", pt_error_code::pte_nosync)
        .value("pte_bad_opc", pt_error_code::pte_bad_opc)
        .value("pte_bad_packet", pt_error_code::pte_bad_packet)
        .value("pte_bad_context", pt_error_code::pte_bad_context)
        .value("pte_eos", pt_error_code::pte_eos)
        .value("pte_bad_query", pt_error_code::pte_bad_query)
        .value("pte_nomem", pt_error_code::pte_nomem)
        .value("pte_bad_config", pt_error_code::pte_bad_config)
        .value("pte_noip", pt_error_code::pte_noip)
        .value("pte_ip_suppressed", pt_error_code::pte_ip_suppressed)
        .value("pte_nomap", pt_error_code::pte_nomap)
        .value("pte_bad_insn", pt_error_code::pte_bad_insn)
        .value("pte_no_time", pt_error_code::pte_no_time)
        .value("pte_no_cbr", pt_error_code::pte_no_cbr)
        .value("pte_bad_image", pt_error_code::pte_bad_image)
        .value("pte_bad_lock", pt_error_code::pte_bad_lock)
        .value("pte_not_supported", pt_error_code::pte_not_supported)
        .value("pte_retstack_empty", pt_error_code::pte_retstack_empty)
        .value("pte_bad_retcomp", pt_error_code::pte_bad_retcomp)
        .value("pte_bad_status_update", pt_error_code::pte_bad_status_update)
        .value("pte_no_enable", pt_error_code::pte_no_enable)
        .value("pte_event_ignored", pt_error_code::pte_event_ignored)
        .value("pte_overflow", pt_error_code::pte_overflow)
        .value("pte_bad_file", pt_error_code::pte_bad_file)
        .value("pte_bad_cpu", pt_error_code::pte_bad_cpu)
        .export_values();
}
