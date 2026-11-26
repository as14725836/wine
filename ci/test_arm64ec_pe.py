"""Synthetic binary tests; no Wine build, compiler or external PE tool is used.

Run from the repository root with:
    python -B -m unittest discover -s ci -p test_arm64ec_pe.py -v
"""

import json
from pathlib import Path
import random
import struct
import tempfile
import unittest

from arm64ec_pe import verify_hybrid_pe


_PE_OFFSET = 0x80
_OPTIONAL = _PE_OFFSET + 24
_SECTION_TABLE = _OPTIONAL + 240
_RAW = 0x400
_SECTION_RVA = 0x1000
_SECTION_SIZE = 0x1000
_IMAGE_BASE = 0x180000000
_CONFIG_RVA = 0x1100
_METADATA_RVA = 0x1300
_MAP_RVA = 0x1400
_DYNAMIC_RVA = 0x1800


def _file_offset(rva):
    return _RAW + rva - _SECTION_RVA


def _put(data, fmt, offset, *values):
    struct.pack_into(fmt, data, offset, *values)


def _record(version=1, symbol=6, payload=None, extra_header=b""):
    if payload is None:
        # IMAGE_BASE_RELOCATION plus one VALUE fixup and its two-byte value.
        # 0x5100 = offset 0x100, type VALUE, size 2 bytes.
        payload = struct.pack("<IIHH", 0x1000, 12, 0x5100, 0x1234)
    if version == 1:
        return struct.pack("<QI", symbol, len(payload)) + payload
    header_size = 24 + len(extra_header)
    return struct.pack("<IIQII", header_size, len(payload), symbol, 0, 0) + extra_header + payload


def _set_records(data, version=1, records=None):
    if records is None:
        records = [_record(version)]
    payload = b"".join(records)
    table = _file_offset(_DYNAMIC_RVA)
    _put(data, "<II", table, version, len(payload))
    data[table + 8:table + 8 + len(payload)] = payload


def _image(version=1):
    data = bytearray(_RAW + _SECTION_SIZE)
    data[0:2] = b"MZ"
    _put(data, "<I", 0x3C, _PE_OFFSET)
    data[_PE_OFFSET:_PE_OFFSET + 4] = b"PE\0\0"
    _put(data, "<HHIIIHH", _PE_OFFSET + 4, 0xAA64, 1, 0, 0, 0, 240, 0x2022)
    _put(data, "<H", _OPTIONAL, 0x20B)
    _put(data, "<Q", _OPTIONAL + 24, _IMAGE_BASE)
    _put(data, "<II", _OPTIONAL + 32, 0x1000, 0x200)
    _put(data, "<II", _OPTIONAL + 56, 0x3000, _RAW)
    _put(data, "<I", _OPTIONAL + 108, 16)
    _put(data, "<II", _OPTIONAL + 112 + 10 * 8, _CONFIG_RVA, 0xF8)
    data[_SECTION_TABLE:_SECTION_TABLE + 8] = b".rdata\0\0"
    _put(data, "<IIII", _SECTION_TABLE + 8,
         _SECTION_SIZE, _SECTION_RVA, _SECTION_SIZE, _RAW)
    _put(data, "<I", _SECTION_TABLE + 36, 0x60000020)
    config = _file_offset(_CONFIG_RVA)
    _put(data, "<I", config, 0xF8)
    _put(data, "<Q", config + 0xC8, _IMAGE_BASE + _METADATA_RVA)
    _put(data, "<IH", config + 0xE0, _DYNAMIC_RVA - _SECTION_RVA, 1)
    _put(data, "<III", _file_offset(_METADATA_RVA), 2, _MAP_RVA, 2)
    _put(data, "<IIII", _file_offset(_MAP_RVA), 0x1500, 0x20, 0x1541, 0x20)
    _set_records(data, version)
    return data


_META_SECTION = (".meta", 0x1000, 0x1000, 0x1000, 0x40000040)
_EXEC_A = (".codea", 0x2000, 0x650, 0x400, 0x60000020)
_EXEC_B = (".codeb", 0x3000, 0x380, 0x200, 0x60000020)


def _span_file_offset(data, rva):
    """Locate fixture bytes without assuming section-table order or header size."""
    count = struct.unpack_from("<H", data, _PE_OFFSET + 6)[0]
    for index in range(count):
        header = _SECTION_TABLE + index * 40
        section_rva, raw_size, raw_offset = struct.unpack_from("<III", data, header + 12)
        if section_rva <= rva < section_rva + raw_size:
            return raw_offset + rva - section_rva
    raise ValueError("fixture RVA is not file-backed: {:#x}".format(rva))


def _span_image(sections=None, entries=None):
    """Keep metadata file-backed in .meta; describe independent code bodies.

    Section tuples are (name, RVA, VirtualSize, SizeOfRawData, Characteristics).
    The input order is the original PE section order, including the DVRT index.
    """
    if sections is None:
        sections = [_META_SECTION, _EXEC_A, _EXEC_B]
    if entries is None:
        entries = [(0x2100, 0x20), (0x2141, 0x20)]
    source = _image()
    headers_size = (_SECTION_TABLE + 40 * len(sections) + 0x1FF) & ~0x1FF
    data = bytearray(headers_size + sum(section[3] for section in sections))
    data[:_SECTION_TABLE] = source[:_SECTION_TABLE]
    _put(data, "<H", _PE_OFFSET + 6, len(sections))
    image_end = max(rva + max(virtual_size, raw_size)
                    for _, rva, virtual_size, raw_size, _ in sections)
    _put(data, "<II", _OPTIONAL + 56, (image_end + 0xFFF) & ~0xFFF, headers_size)
    raw_offset = headers_size
    metadata_index = None
    for index, (name, rva, virtual_size, raw_size, flags) in enumerate(sections):
        header = _SECTION_TABLE + index * 40
        data[header:header + 8] = name.encode("ascii").ljust(8, b"\0")
        _put(data, "<IIII", header + 8,
             virtual_size, rva, raw_size, raw_offset if raw_size else 0)
        _put(data, "<I", header + 36, flags)
        # Reuse only source bytes actually present in this section's raw body.
        copy_start = max(rva, _SECTION_RVA)
        copy_end = min(rva + raw_size, _SECTION_RVA + _SECTION_SIZE)
        if copy_start < copy_end:
            target = raw_offset + copy_start - rva
            data[target:target + copy_end - copy_start] = source[
                _file_offset(copy_start):_file_offset(copy_end)]
        if name == ".meta":
            metadata_index = index + 1
        raw_offset += raw_size
    if metadata_index is None:
        raise ValueError("fixture needs a .meta section")
    _put(data, "<H", _span_file_offset(data, _CONFIG_RVA) + 0xE4, metadata_index)
    _put(data, "<I", _span_file_offset(data, _METADATA_RVA) + 8, len(entries))
    table = _span_file_offset(data, _MAP_RVA)
    for index, (tagged_start, length) in enumerate(entries):
        _put(data, "<II", table + index * 8, tagged_start, length)
    return data


class VerifyHybridPETests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "ntdll.dll"

    def verify(self, data):
        self.path.write_bytes(data)
        report = verify_hybrid_pe(self.path)
        self.assertIsInstance(report, dict)
        self.assertEqual(set(report), {"ok", "path", "errors", "checks", "evidence"})
        self.assertIs(type(report["ok"]), bool)
        self.assertEqual(report["path"], str(self.path))
        self.assertIsInstance(report["errors"], list)
        self.assertTrue(all(isinstance(item, str) for item in report["errors"]))
        self.assertTrue(all(type(value) is bool for value in report["checks"].values()))
        json.dumps(report, allow_nan=False)
        return report

    def assert_bad(self, data, reason):
        report = self.verify(data)
        self.assertFalse(report["ok"], report)
        self.assertTrue(report["errors"], report)
        self.assertIn(reason.lower(), " ".join(report["errors"]).lower())
        return report

    def assert_failed_entry(self, report, index, tagged_start, length,
                            start_section, end_section):
        failed = report["evidence"]["code_map"]["failed_entry"]
        self.assertEqual(set(failed), {"index", "type", "start_rva", "length",
                                       "end_rva", "start_section", "end_section",
                                       "failure"})
        self.assertEqual(failed["index"], index)
        self.assertEqual(failed["type"], tagged_start & 3)
        self.assertEqual(failed["start_rva"], tagged_start & ~3)
        self.assertEqual(failed["length"], length)
        self.assertEqual(failed["end_rva"], (tagged_start & ~3) + length)
        self.assertIsInstance(failed["failure"], str)
        self.assertTrue(failed["failure"])
        fields = {"index", "name", "rva", "virtual_size", "raw_size", "characteristics"}
        for key, expected_index in (("start_section", start_section),
                                    ("end_section", end_section)):
            if expected_index is None:
                self.assertIsNone(failed[key])
            else:
                self.assertIsInstance(failed[key], dict)
                self.assertTrue(fields <= set(failed[key]))
                self.assertIs(type(failed[key]["index"]), int)
                self.assertEqual(failed[key]["index"], expected_index)
        return failed

    def test_valid_v1_and_evidence(self):
        report = self.verify(_image())
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["errors"], [])
        self.assertTrue(all(report["checks"].values()))
        evidence = report["evidence"]
        self.assertEqual(evidence["machine"], 0xAA64)
        self.assertEqual(evidence["optional_header_magic"], 0x20B)
        self.assertEqual(evidence["chpe_metadata"]["rva"], _METADATA_RVA)
        self.assertEqual(evidence["code_map"]["type_counts"], {"ARM64": 1, "ARM64EC": 1, "x64": 0})
        self.assertEqual(evidence["code_map"]["entries_sample"][1]["start_rva"], 0x1540)
        self.assertEqual(evidence["dynamic_relocations"]["symbols"], [6])
        self.assertEqual(evidence["dynamic_relocations"]["size"], len(_record()))
        self.assertEqual(evidence["dynamic_relocations"]["locator"], "section_offset")

    def test_valid_v2_extended_header(self):
        data = _image(2)
        records = [_record(2, 3), _record(2, 6, extra_header=b"abcdefgh")]
        _set_records(data, 2, records)
        report = self.verify(data)
        self.assertTrue(report["ok"], report)
        evidence = report["evidence"]["dynamic_relocations"]
        self.assertEqual(evidence["entry_count"], 2)
        self.assertEqual(evidence["arm64x_record_count"], 1)
        self.assertEqual(evidence["entries_sample"][1]["header_size"], 32)
        self.assertEqual(evidence["symbols"], [3, 6])

    def test_legacy_va_locator(self):
        data = _image()
        config = _file_offset(_CONFIG_RVA)
        _put(data, "<Q", config + 0xC0, _IMAGE_BASE + _DYNAMIC_RVA)
        _put(data, "<IH", config + 0xE0, 0, 0)
        report = self.verify(data)
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["evidence"]["dynamic_relocations"]["locator"], "va")
        _put(data, "<I", config, 0xD0)
        self.assertTrue(self.verify(data)["ok"])

    def test_agreeing_dual_locators(self):
        data = _image()
        _put(data, "<Q", _file_offset(_CONFIG_RVA) + 0xC0, _IMAGE_BASE + _DYNAMIC_RVA)
        self.assertTrue(self.verify(data)["ok"])

    def test_machine_and_magic(self):
        for machine in (0x8664, 0xA641, 0, 0xA64E):
            with self.subTest(machine=machine):
                data = _image()
                _put(data, "<H", _PE_OFFSET + 4, machine)
                self.assert_bad(data, "Machine")
        data = _image()
        _put(data, "<H", _OPTIONAL, 0x10B)
        self.assert_bad(data, "PE32+")

    def test_signatures(self):
        for offset in (0, _PE_OFFSET):
            with self.subTest(offset=offset):
                data = _image()
                data[offset] = 0
                self.assert_bad(data, "signature")
        data = _image()
        _put(data, "<I", 0x3C, 4)
        self.assert_bad(data, "e_lfanew")

    def test_header_sizes(self):
        changes = [
            (_PE_OFFSET + 20, "<H", 0, "too short"),
            (_PE_OFFSET + 20, "<H", 0xFFFF, "optional header"),
            (_OPTIONAL + 108, "<I", 17, "directory"),
            (_OPTIONAL + 108, "<I", 10, "load-config"),
            (_OPTIONAL + 60, "<I", 0x100, "SizeOfHeaders"),
            (_OPTIONAL + 60, "<I", 0x4000, "SizeOfHeaders"),
            (_OPTIONAL + 56, "<I", 0, "SizeOfHeaders"),
            (_PE_OFFSET + 6, "<H", 0, "no sections"),
            (_PE_OFFSET + 6, "<H", 0xFFFF, "section table"),
        ]
        for offset, fmt, value, reason in changes:
            with self.subTest(offset=offset, value=value):
                data = _image()
                _put(data, fmt, offset, value)
                self.assert_bad(data, reason)

    def test_section_bounds_and_overlaps(self):
        changes = [
            (_SECTION_TABLE + 20, 0xFFFFFF00, "raw data"),
            (_SECTION_TABLE + 20, 0x300, "overlapping"),
            (_SECTION_TABLE + 12, 0, "overlapping"),
            (_SECTION_TABLE + 8, 0xFFFFFFFF, "SizeOfImage"),
            (_SECTION_TABLE + 12, 0xFFFFFFF0, "SizeOfImage"),
        ]
        for offset, value, reason in changes:
            with self.subTest(offset=offset, value=value):
                data = _image()
                _put(data, "<I", offset, value)
                self.assert_bad(data, reason)
        data = _image()
        _put(data, "<H", _PE_OFFSET + 6, 2)
        data[_SECTION_TABLE + 40:_SECTION_TABLE + 80] = data[_SECTION_TABLE:_SECTION_TABLE + 40]
        self.assert_bad(data, "overlapping")

    def test_load_config_bounds(self):
        entry = _OPTIONAL + 112 + 10 * 8
        cases = [(0, 0xF8, "absent"), (0x2100, 0xF8, "not mapped"),
                 (0x1FF0, 0xF8, "file-backed"), (_CONFIG_RVA, 3, "too short"),
                 (_CONFIG_RVA, 0xCF, "CHPEMetadataPointer"),
                 (_CONFIG_RVA, 0xFFFFFFFF, "RVA span")]
        for rva, size, reason in cases:
            with self.subTest(rva=rva, size=size):
                data = _image()
                _put(data, "<II", entry, rva, size)
                self.assert_bad(data, reason)
        data = _image()
        _put(data, "<I", _file_offset(_CONFIG_RVA), 0xCF)
        self.assert_bad(data, "CHPEMetadataPointer")

    def test_metadata_pointer_and_version(self):
        for va, reason in ((0, "zero"), (_IMAGE_BASE - 1, "VA"),
                           (_IMAGE_BASE + (1 << 32), "VA"),
                           (_IMAGE_BASE + 0x1FFC, "file-backed"),
                           (_IMAGE_BASE + 0x2100, "not mapped")):
            with self.subTest(va=va):
                data = _image()
                _put(data, "<Q", _file_offset(_CONFIG_RVA) + 0xC8, va)
                self.assert_bad(data, reason)
        for version in (0, 1, 3, 0xFFFFFFFF):
            with self.subTest(version=version):
                data = _image()
                _put(data, "<I", _file_offset(_METADATA_RVA), version)
                self.assert_bad(data, "Version must be 2")

    def test_code_map_rva_and_count(self):
        cases = [(0, 2, "RVA is zero"), (_MAP_RVA, 0, "count"),
                 (_MAP_RVA, 0xFFFFFFFF, "count"),
                 (0xFFFFFFFC, 2, "overflow"), (0x1FFC, 2, "file-backed"),
                 (0x2100, 2, "not mapped")]
        for rva, count, reason in cases:
            with self.subTest(rva=rva, count=count):
                data = _image()
                _put(data, "<II", _file_offset(_METADATA_RVA) + 4, rva, count)
                self.assert_bad(data, reason)

    def test_code_map_uses_low_two_bits(self):
        data = _image()
        # Clearing only bit zero would misread x64 type 2 as ordinary ARM64.
        _put(data, "<I", _file_offset(_MAP_RVA), 0x1502)
        report = self.assert_bad(data, "no ARM64 (type 0)")
        self.assertEqual(report["evidence"]["code_map"]["type_counts"]["x64"], 1)
        data = _image()
        _put(data, "<I", _file_offset(_MAP_RVA) + 8, 0x1540)
        self.assert_bad(data, "no ARM64EC")
        data = _image()
        _put(data, "<I", _file_offset(_MAP_RVA) + 8, 0x1543)
        self.assert_bad(data, "unknown type 3")

    def test_positive_range_lengths_and_bounds(self):
        cases = [(0x1500, 0, "zero length"), (0x1500, 0xFFFFFFFF, "RVA span"),
                 (0x1FF0, 0x20, "CodeMap entry 0"), (0x2100, 4, "CodeMap entry 0"),
                 (0xFFFFFFFC, 8, "RVA span"), (0x3FC, 8, "CodeMap entry 0")]
        for start, length, reason in cases:
            with self.subTest(start=start, length=length):
                data = _image()
                _put(data, "<II", _file_offset(_MAP_RVA), start, length)
                self.assert_bad(data, reason)

    def test_virtual_only_executable_range_accepted(self):
        data = _image()
        _put(data, "<I", _SECTION_TABLE + 8, 0x1800)
        _put(data, "<II", _file_offset(_MAP_RVA), 0x2200, 4)
        report = self.verify(data)
        self.assertTrue(report["ok"], report)

    def test_separate_nonexecutable_metadata_and_executable_code(self):
        report = self.verify(_span_image())
        self.assertTrue(report["ok"], report)
        self.assertTrue(all(report["checks"].values()))

    def test_executable_spans_join_adjacent_bodies_across_canonical_padding(self):
        # A ends at 0x2650, its alignment padding ends where B begins: 0x3000.
        for start, end in ((0x2100, 0x3250), (0x2500, 0x3004),
                           (0x2000, 0x3380), (0x264C, 0x3001)):
            with self.subTest(start=start, end=end):
                report = self.verify(_span_image(entries=[
                    (start, end - start), (0x2141, 4)]))
                self.assertTrue(report["ok"], report)

    def test_executable_span_exactly_adjacent_without_padding(self):
        section = (".full", 0x2000, 0x1000, 0x200, 0x60000020)
        report = self.verify(_span_image(
            sections=[_META_SECTION, section, _EXEC_B],
            entries=[(0x2FFC, 8), (0x2141, 4)]))
        self.assertTrue(report["ok"], report)

    def test_executable_virtual_tail_is_part_of_body(self):
        # A's raw data ends at 0x2400, but VirtualSize extends to 0x2650.
        for start, length in ((0x23FC, 8), (0x2400, 4), (0x2500, 0x150)):
            with self.subTest(start=start, length=length):
                report = self.verify(_span_image(entries=[
                    (start, length), (0x2141, 4)]))
                self.assertTrue(report["ok"], report)

    def test_executable_body_uses_maximum_of_virtual_and_raw_sizes(self):
        for virtual_size in (0, 0x100):
            with self.subTest(virtual_size=virtual_size):
                section = (".raw", 0x2000, virtual_size, 0x400, 0x60000020)
                report = self.verify(_span_image(
                    sections=[_META_SECTION, section, _EXEC_B],
                    entries=[(0x2300, 0x100), (0x2105, 1)]))
                self.assertTrue(report["ok"], report)

    def test_zero_raw_executable_body_and_spans_entering_and_leaving_it(self):
        sections = [_META_SECTION, _EXEC_A,
                    (".zero", 0x3000, 0x180, 0, 0x60000020),
                    (".last", 0x4000, 0x200, 0x200, 0x60000020)]
        entries = [(0x3000, 0x180), (0x2501, 0xB04),
                   (0x3100, 0xF04), (0x2501, 0x1C04)]
        report = self.verify(_span_image(sections=sections, entries=entries))
        self.assertTrue(report["ok"], report)

    def test_empty_nonexecutable_section_does_not_split_executable_run(self):
        sections = [_META_SECTION, _EXEC_A,
                    (".empty", 0x3000, 0, 0, 0x40000040), _EXEC_B]
        report = self.verify(_span_image(sections=sections, entries=[
            (0x2500, 0xB04), (0x2141, 4)]))
        self.assertTrue(report["ok"], report)

    def test_nonpage_aligned_overlapping_and_unsorted_code_map_ranges(self):
        entries = [(0x2201, 0x100), (0x2100, 0x180),
                   (0x2142, 0x21), (0x2105, 1)]
        report = self.verify(_span_image(entries=entries))
        self.assertTrue(report["ok"], report)
        sample = report["evidence"]["code_map"]["entries_sample"]
        self.assertEqual([item["start_rva"] for item in sample],
                         [start & ~3 for start, _ in entries])
        self.assertEqual([item["length"] for item in sample],
                         [length for _, length in entries])

    def test_unsorted_sections_preserve_original_one_based_dvrt_index(self):
        sections = [_EXEC_B, _META_SECTION, _EXEC_A]
        data = _span_image(sections=sections, entries=[
            (0x2500, 0xB04), (0x2141, 4)])
        report = self.verify(data)
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["evidence"]["dynamic_relocations"]["locator"],
                         "section_offset")
        # .meta is originally section 2, although it sorts first by RVA.
        _put(data, "<H", _span_file_offset(data, _CONFIG_RVA) + 0xE4, 1)
        self.assert_bad(data, "raw data")

    def test_code_spans_reject_headers_and_nonexecutable_endpoints(self):
        for start, length in ((0, 4), (0x200, 4), (0x3FC, 8),
                              (0x1100, 4), (0x1100, 0x1004)):
            with self.subTest(start=start, length=length):
                data = _span_image(entries=[(start, length), (0x2141, 4)])
                self.assert_bad(data, "CodeMap entry 0")
        # The name .text cannot grant execution permission to a nonexec body.
        sections = [_META_SECTION, _EXEC_A,
                    (".text", 0x3000, 0x380, 0x200, 0x40000040)]
        data = _span_image(sections=sections, entries=[
            (0x2100, 0x1004), (0x2141, 4)])
        self.assert_bad(data, "CodeMap entry 0")

    def test_code_spans_reject_nonexecutable_intermediate_section(self):
        for raw_size in (0, 0x200):
            with self.subTest(raw_size=raw_size):
                sections = [_META_SECTION, _EXEC_A,
                            (".data", 0x3000, 0x380, raw_size, 0x40000040),
                            (".last", 0x4000, 0x380, 0x200, 0x60000020)]
                data = _span_image(sections=sections, entries=[
                    (0x2100, 0x2004), (0x2141, 4)])
                self.assert_bad(data, "CodeMap entry 0")

    def test_code_spans_reject_arbitrary_holes_between_executable_sections(self):
        sections = [_META_SECTION, _EXEC_A,
                    (".far", 0x4000, 0x380, 0x200, 0x60000020)]
        for start, end in ((0x2100, 0x4104), (0x3000, 0x4104)):
            with self.subTest(start=start, end=end):
                data = _span_image(sections=sections, entries=[
                    (start, end - start), (0x2141, 4)])
                self.assert_bad(data, "CodeMap entry 0")

    def test_code_spans_cannot_start_or_end_in_internal_padding(self):
        for start, end in ((0x2800, 0x3100), (0x2650, 0x3004),
                           (0x2500, 0x2651), (0x2500, 0x3000),
                           (0x2800, 0x2804)):
            with self.subTest(start=start, end=end):
                data = _span_image(entries=[(start, end - start), (0x2141, 4)])
                self.assert_bad(data, "CodeMap entry 0")

    def test_code_spans_cannot_end_in_final_alignment_tail(self):
        for start, end in ((0x3300, 0x3381), (0x3300, 0x4000),
                           (0x3380, 0x3384), (0x3800, 0x3804)):
            with self.subTest(start=start, end=end):
                data = _span_image(entries=[(start, end - start), (0x2141, 4)])
                self.assert_bad(data, "CodeMap entry 0")

    def test_code_span_size_of_image_and_32_bit_sum_boundaries(self):
        sections = [_META_SECTION, _EXEC_A,
                    (".last", 0x3000, 0x1000, 0x200, 0x60000020)]
        report = self.verify(_span_image(sections=sections, entries=[
            (0x3FFC, 4), (0x2141, 4)]))
        self.assertTrue(report["ok"], report)
        for start, length in ((0x3FFC, 5), (0x4000, 4),
                              (0xFFFFFFFC, 4), (0xFFFFFFFC, 8),
                              (0x2100, 0xFFFFFFFF), (0x2100, 0)):
            with self.subTest(start=start, length=length):
                data = _span_image(sections=sections, entries=[
                    (start, length), (0x2141, 4)])
                self.assert_bad(data, "CodeMap entry 0")

    def test_section_alignment_must_be_supported_power_of_two(self):
        for alignment in (0, 1, 0x200, 0x800, 0xC00, 0x1800, 0x3000, 0xFFFFFFFF):
            with self.subTest(alignment=alignment):
                data = _image()
                _put(data, "<I", _OPTIONAL + 32, alignment)
                self.assert_bad(data, "SectionAlignment")

    def test_metadata_structures_still_require_file_backing(self):
        sections = [(".meta", 0x1000, 0x1000, 0xA00, 0x40000040),
                    _EXEC_A, _EXEC_B]
        for structure in ("load-config", "CHPE", "CodeMap", "DVRT"):
            with self.subTest(structure=structure):
                data = _span_image(sections=sections)
                config = _span_file_offset(data, _CONFIG_RVA)
                if structure == "load-config":
                    _put(data, "<II", _OPTIONAL + 112 + 10 * 8, 0x1C00, 0xF8)
                elif structure == "CHPE":
                    _put(data, "<Q", config + 0xC8, _IMAGE_BASE + 0x1C00)
                elif structure == "CodeMap":
                    _put(data, "<II", _span_file_offset(data, _METADATA_RVA) + 4,
                         0x1C00, 2)
                else:
                    _put(data, "<Q", config + 0xC0, _IMAGE_BASE + 0x1C00)
                    _put(data, "<IH", config + 0xE0, 0, 0)
                self.assert_bad(data, "file-backed")
        data = _span_image(sections=sections)
        _put(data, "<I", _span_file_offset(data, _CONFIG_RVA) + 0xE0, 0xC00)
        self.assert_bad(data, "raw data")

    def test_metadata_structures_cannot_span_adjacent_file_backed_sections(self):
        for structure in ("load-config", "CHPE", "CodeMap"):
            with self.subTest(structure=structure):
                data = _span_image()
                if structure == "load-config":
                    _put(data, "<II", _OPTIONAL + 112 + 10 * 8, 0x1FF0, 0xF8)
                elif structure == "CHPE":
                    _put(data, "<Q", _span_file_offset(data, _CONFIG_RVA) + 0xC8,
                         _IMAGE_BASE + 0x1FFC)
                else:
                    _put(data, "<II", _span_file_offset(data, _METADATA_RVA) + 4,
                         0x1FF8, 2)
                self.assert_bad(data, "file-backed")

    def test_dvrt_header_and_body_cannot_span_adjacent_file_backed_sections(self):
        for locator in ("va", "section_offset"):
            for table_rva in (0x1FFC, 0x1FF0):
                with self.subTest(locator=locator, table_rva=table_rva):
                    data = _span_image()
                    config = _span_file_offset(data, _CONFIG_RVA)
                    if locator == "va":
                        _put(data, "<Q", config + 0xC0, _IMAGE_BASE + table_rva)
                        _put(data, "<IH", config + 0xE0, 0, 0)
                    else:
                        _put(data, "<I", config + 0xE0, table_rva - 0x1000)
                    table = _span_file_offset(data, table_rva)
                    record = _record()
                    _put(data, "<II", table, 1, len(record))
                    data[table + 8:table + 8 + len(record)] = record
                    reason = "raw data" if locator == "section_offset" and table_rva == 0x1FFC else "file-backed"
                    self.assert_bad(data, reason)

    def test_valid_x64_additional_range(self):
        data = _image()
        _put(data, "<I", _file_offset(_METADATA_RVA) + 8, 3)
        _put(data, "<II", _file_offset(_MAP_RVA) + 16, 0x1582, 4)
        report = self.verify(data)
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["evidence"]["code_map"]["type_counts"]["x64"], 1)

    def test_dynamic_section_is_one_based(self):
        data = _image()
        config = _file_offset(_CONFIG_RVA)
        _put(data, "<H", config + 0xE4, 2)
        self.assert_bad(data, "one-based")
        _put(data, "<H", config + 0xE4, 0)
        self.assert_bad(data, "no section index")
        _put(data, "<I", config + 0xE0, 0)
        self.assert_bad(data, "locator is missing")

    def test_dynamic_locator_bounds_and_disagreement(self):
        for offset in (0xFFD, 0x1000, 0xFFFFFFFF):
            with self.subTest(offset=offset):
                data = _image()
                _put(data, "<I", _file_offset(_CONFIG_RVA) + 0xE0, offset)
                self.assert_bad(data, "raw data")
        data = _image()
        _put(data, "<Q", _file_offset(_CONFIG_RVA) + 0xC0, _IMAGE_BASE + _DYNAMIC_RVA + 8)
        self.assert_bad(data, "locators disagree")

    def test_dynamic_versions_and_sizes(self):
        dynamic = _file_offset(_DYNAMIC_RVA)
        for version in (0, 3, 0xFFFFFFFF):
            with self.subTest(version=version):
                data = _image()
                _put(data, "<I", dynamic, version)
                self.assert_bad(data, "unsupported")
        for size, reason in ((0, "empty"), (0xFFFFFFFF, "RVA span"),
                             (0x800, "file-backed"), (11, "v1 record"),
                             (23, "fixup payload"), (25, "v1 record")):
            with self.subTest(size=size):
                data = _image()
                _put(data, "<I", dynamic + 4, size)
                self.assert_bad(data, reason)

    def test_symbol_six_is_a_record_not_substring(self):
        data = _image()
        _set_records(data, records=[_record(symbol=3, payload=b"\x06\0\0\0\0\0\0\0")])
        self.assert_bad(data, "no ARM64X Symbol 6")
        data = _image()
        _set_records(data, records=[_record(payload=b"")])
        self.assert_bad(data, "empty fixup payload")

    def test_all_records_checked_after_arm64x(self):
        for version in (1, 2):
            with self.subTest(version=version):
                data = _image(version)
                _set_records(data, version, [_record(version), b"\0"])
                self.assert_bad(data, "record")

    def test_v2_record_boundaries(self):
        table = _file_offset(_DYNAMIC_RVA)
        for header_size, reason in ((0, "smaller than 24"), (23, "smaller than 24"),
                                    (37, "record header"), (0xFFFFFFFF, "record header")):
            with self.subTest(header_size=header_size):
                data = _image(2)
                _put(data, "<I", table + 8, header_size)
                self.assert_bad(data, reason)
        data = _image(2)
        _put(data, "<I", table + 12, 0xFFFFFFFF)
        self.assert_bad(data, "fixup payload")
        data = _image(2)
        _put(data, "<I", table + 4, 23)
        self.assert_bad(data, "v2 record")

    def test_failed_span_evidence_has_original_section_indices(self):
        sections = [_EXEC_B, _META_SECTION, _EXEC_A]
        for start, end, start_section, end_section in (
                (0x200, 0x204, None, None),
                (0x1100, 0x1104, 2, 2),
                (0x2800, 0x3100, None, 1),
                (0x2500, 0x2800, 3, None)):
            with self.subTest(start=start, end=end):
                report = self.assert_bad(_span_image(
                    sections, [(start | 1, end - start), (0x2140, 4)]),
                    "CodeMap entry 0")
                self.assert_failed_entry(report, 0, start | 1, end - start,
                                         start_section, end_section)
        sections = [(".codeb", 0x4000, 0x380, 0x200, 0x60000020),
                    _META_SECTION, _EXEC_A]
        report = self.assert_bad(_span_image(
            sections, [(0x2501, 0x1B04), (0x2140, 4)]), "CodeMap entry 0")
        failed = self.assert_failed_entry(report, 0, 0x2501, 0x1B04, 3, 1)
        self.assertEqual(failed["start_section"]["rva"], 0x2000)
        self.assertEqual(failed["end_section"]["rva"], 0x4000)

    def test_failed_entry_beyond_samples_retains_bounded_section_evidence(self):
        sections = [_META_SECTION,
                    (".c00", 0x2000, 0x400, 0x200, 0x60000020)]
        sections.extend((".c{:02d}".format(index), (index + 3) * 0x1000,
                         0x400, 0x200, 0x60000020) for index in range(1, 39))
        entries = [(0x2100 | (index % 2), 4) for index in range(39)]
        bad_length = sections[-1][1] + 4 - 0x2100
        entries.append((0x2101, bad_length))
        report = self.assert_bad(_span_image(sections, entries), "CodeMap entry 39")
        code_map = report["evidence"]["code_map"]
        self.assertEqual(code_map["count"], 40)
        self.assertEqual(len(code_map["entries_sample"]), 32)
        self.assertTrue(code_map["entries_sample_truncated"])
        failed = self.assert_failed_entry(report, 39, 0x2101, bad_length, 2, 40)
        self.assertEqual(failed["end_section"]["rva"], sections[-1][1])
        sample = report["evidence"]["sections_sample"]
        self.assertEqual(len(sample), 32)
        self.assertTrue({"index", "name", "rva", "virtual_size", "raw_size",
                         "characteristics"} <= set(sample[0]))
        self.assertEqual([section["index"] for section in sample], list(range(1, 33)))
        self.assertLess(len(json.dumps(report)), 32768)

    def test_bounded_evidence_samples(self):
        data = _image()
        _put(data, "<I", _file_offset(_METADATA_RVA) + 8, 40)
        for index in range(40):
            _put(data, "<II", _file_offset(_MAP_RVA) + index * 8, 0x1600 | (index % 2), 4)
        report = self.verify(data)
        self.assertTrue(report["ok"], report)
        evidence = report["evidence"]["code_map"]
        self.assertEqual(evidence["count"], 40)
        self.assertEqual(len(evidence["entries_sample"]), 32)
        self.assertTrue(evidence["entries_sample_truncated"])
        _set_records(data, records=[_record() for _ in range(40)])
        report = self.verify(data)
        self.assertTrue(report["ok"], report)
        evidence = report["evidence"]["dynamic_relocations"]
        self.assertEqual(evidence["arm64x_record_count"], 40)
        self.assertEqual(len(evidence["entries_sample"]), 32)
        self.assertTrue(evidence["entries_sample_truncated"])

    def test_every_truncated_prefix_fails_cleanly(self):
        data = _image()
        for size in range(len(data)):
            with self.subTest(size=size):
                report = self.verify(data[:size])
                self.assertFalse(report["ok"], report)
                self.assertTrue(report["errors"], report)

    def test_deterministic_byte_mutations_never_escape(self):
        rng = random.Random(20261126)
        original = _image()
        for case in range(300):
            with self.subTest(case=case):
                data = original.copy()
                for _ in range(rng.randint(1, 8)):
                    data[rng.randrange(len(data))] = rng.randrange(256)
                self.verify(data)

    def test_io_errors_and_bad_path_types(self):
        missing = verify_hybrid_pe(self.path)
        self.assertFalse(missing["ok"])
        self.assertIn("FileNotFoundError", missing["errors"][0])
        directory = verify_hybrid_pe(self.temp.name)
        self.assertFalse(directory["ok"])
        for path in (None, 42, b"binary-path", "embedded\0nul"):
            with self.subTest(path=path):
                report = verify_hybrid_pe(path)
                self.assertFalse(report["ok"])
                self.assertTrue(report["errors"])
                json.dumps(report, allow_nan=False)


if __name__ == "__main__":
    unittest.main()
