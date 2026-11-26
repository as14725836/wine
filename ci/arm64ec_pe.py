"""Offline structural verification of an ARM64X PE, using only the standard library.

Import ``verify_hybrid_pe`` and gate on report["ok"].  Expected format and I/O
failures are returned in report["errors"], not raised.  Integers in ``evidence``
are numeric (not hexadecimal strings), and every report is JSON serializable.

The binary layout follows this checkout's include/winnt.h and
tools/winedump/pe.c: PE32+ load-config offsets 0xc0/0xc8/0xe0/0xe4,
IMAGE_ARM64EC_METADATA's first three DWORDs, two-bit CodeMap tags, and
packed DVRT v1/v2 records.  DVRT Size excludes its eight-byte table header;
DynamicValueRelocTableSection is one-based.

This is an identity/structure gate, not a loader, signature verifier or proof
that the mapped bytes implement either instruction set.  ARM64X fixup payloads
are bounded but are not applied or interpreted.  No subprocess, compiler,
network access, external parser, or optional package is used.
"""

import os
from pathlib import Path
import struct

__all__ = ["verify_hybrid_pe"]

_ARM64 = 0xAA64
_PE32_PLUS = 0x20B
_U32_END = 1 << 32
_MAX_ENTRIES = 1_000_000
_SAMPLE_ENTRIES = 32
_TYPE_NAMES = ("ARM64", "ARM64EC", "x64")


class _InvalidPE(ValueError):
    pass


def _require(condition, message):
    if not condition:
        raise _InvalidPE(message)


class _PE:
    def __init__(self, data, report):
        self.data = data
        self.report = report
        self.evidence = report["evidence"]
        self.checks = report["checks"]
        self.sections = []

    def bounds(self, offset, size, label, limit=None):
        if limit is None:
            limit = len(self.data)
        _require(offset >= 0 and size >= 0 and offset <= limit
                 and size <= limit - offset,
                 "{}: truncated or out-of-bounds file span".format(label))
        return offset

    def unpack(self, fmt, offset, label):
        self.bounds(offset, struct.calcsize(fmt), label)
        return struct.unpack_from(fmt, self.data, offset)

    def rva(self, address, size, label):
        _require(0 <= address < _U32_END and size > 0
                 and size <= _U32_END - address
                 and address + size <= self.image_size,
                 "{}: invalid or overflowing RVA span".format(label))
        if address < self.headers_size:
            _require(size <= self.headers_size - address,
                     "{}: RVA crosses the header boundary".format(label))
            return self.bounds(address, size, label)
        for section in self.sections:
            relative = address - section["rva"]
            if 0 <= relative < section["mapped_size"]:
                _require(relative <= section["raw_size"]
                         and size <= section["raw_size"] - relative,
                         "{}: RVA is not fully file-backed in one section".format(label))
                return self.bounds(section["raw_offset"] + relative, size, label)
        raise _InvalidPE("{}: RVA is not mapped by a section".format(label))

    def va_rva(self, address, label):
        _require(address >= self.image_base and address - self.image_base < _U32_END,
                 "{}: VA is outside ImageBase-relative RVA space".format(label))
        return address - self.image_base

    @staticmethod
    def nonoverlap(spans, label):
        previous_end = 0
        for start, end in sorted(spans):
            _require(start >= previous_end, "{}: overlapping spans".format(label))
            previous_end = end

    def headers(self):
        self.bounds(0, 64, "DOS header")
        _require(self.data[:2] == b"MZ", "missing MZ signature")
        pe_offset, = self.unpack("<I", 0x3C, "e_lfanew")
        _require(pe_offset >= 64, "e_lfanew overlaps the DOS header")
        self.bounds(pe_offset, 24, "PE signature and COFF header")
        _require(self.data[pe_offset:pe_offset + 4] == b"PE\0\0",
                 "missing PE signature")
        machine, section_count = self.unpack("<HH", pe_offset + 4, "COFF header")
        self.evidence["machine"] = machine
        _require(machine == _ARM64, "COFF Machine must be ARM64 (0xaa64)")
        self.checks["arm64_machine"] = True
        _require(section_count > 0, "PE has no sections")
        optional_size, = self.unpack("<H", pe_offset + 20, "SizeOfOptionalHeader")
        optional = pe_offset + 24
        self.bounds(optional, optional_size, "optional header")
        _require(optional_size >= 112, "optional header is too short for PE32+")
        magic, = self.unpack("<H", optional, "optional header magic")
        self.evidence["optional_header_magic"] = magic
        _require(magic == _PE32_PLUS, "optional header must be PE32+ (0x20b)")
        self.checks["pe32_plus"] = True
        self.image_base, = self.unpack("<Q", optional + 24, "ImageBase")
        self.image_size, self.headers_size = self.unpack("<II", optional + 56,
                                                        "SizeOfImage/SizeOfHeaders")
        directory_count, = self.unpack("<I", optional + 108, "NumberOfRvaAndSizes")
        _require(directory_count <= (optional_size - 112) // 8,
                 "data-directory count exceeds optional-header bounds")
        section_table = optional + optional_size
        self.bounds(section_table, section_count * 40, "section table")
        _require(section_table + section_count * 40 <= self.headers_size
                 <= min(len(self.data), self.image_size),
                 "SizeOfHeaders does not contain the headers or exceeds the image/file")
        raw_spans = [(0, self.headers_size)]
        virtual_spans = [(0, self.headers_size)]
        for index in range(section_count):
            offset = section_table + index * 40
            virtual_size, rva, raw_size, raw_offset = self.unpack(
                "<IIII", offset + 8, "section {}".format(index + 1))
            mapped_size = max(virtual_size, raw_size)
            _require(rva + mapped_size <= min(self.image_size, _U32_END),
                     "section {} exceeds SizeOfImage/RVA space".format(index + 1))
            if raw_size:
                self.bounds(raw_offset, raw_size, "section {} raw data".format(index + 1))
                raw_spans.append((raw_offset, raw_offset + raw_size))
            if mapped_size:
                virtual_spans.append((rva, rva + mapped_size))
            name = self.data[offset:offset + 8].split(b"\0", 1)[0].decode("ascii", "replace")
            self.sections.append({"index": index + 1, "name": name, "rva": rva,
                                  "mapped_size": mapped_size, "raw_size": raw_size,
                                  "raw_offset": raw_offset})
        self.nonoverlap(raw_spans, "section/header file ranges")
        self.nonoverlap(virtual_spans, "section/header RVA ranges")
        self.evidence.update({"image_base": self.image_base, "image_size": self.image_size,
                              "section_count": section_count})
        self.checks["pe_bounds"] = True
        _require(directory_count > 10, "load-config data directory is missing")
        config_rva, config_size = self.unpack("<II", optional + 112 + 10 * 8,
                                               "load-config data directory")
        _require(config_rva != 0 and config_size >= 4,
                 "load-config data directory is absent or too short")
        config = self.rva(config_rva, config_size, "load-config directory")
        declared_size, = self.unpack("<I", config, "load-config Size")
        effective_size = min(config_size, declared_size)
        _require(effective_size >= 0xD0,
                 "load-config Size/directory size does not cover CHPEMetadataPointer")
        metadata_va, = self.unpack("<Q", config + 0xC8, "CHPEMetadataPointer")
        dynamic_va, = self.unpack("<Q", config + 0xC0, "DynamicValueRelocTable")
        dynamic_offset = dynamic_section = 0
        if effective_size >= 0xE6:
            dynamic_offset, dynamic_section = self.unpack("<IH", config + 0xE0,
                                                          "dynamic relocation locator")
        self.evidence["load_config"] = {
            "rva": config_rva, "file_offset": config, "directory_size": config_size,
            "size": declared_size, "chpe_metadata_pointer": metadata_va,
            "dynamic_value_reloc_table": dynamic_va,
            "dynamic_value_reloc_table_offset": dynamic_offset,
            "dynamic_value_reloc_table_section": dynamic_section,
        }
        self.checks["load_config"] = True
        return metadata_va, dynamic_va, dynamic_offset, dynamic_section

    def metadata(self, metadata_va):
        _require(metadata_va != 0, "CHPEMetadataPointer is zero")
        metadata_rva = self.va_rva(metadata_va, "CHPEMetadataPointer")
        metadata = self.rva(metadata_rva, 12, "ARM64EC metadata prefix")
        version, code_map, count = self.unpack("<III", metadata, "ARM64EC metadata prefix")
        self.evidence["chpe_metadata"] = {"va": metadata_va, "rva": metadata_rva,
                                           "file_offset": metadata, "version": version,
                                           "code_map_rva": code_map, "code_map_count": count}
        _require(version == 2, "ARM64EC metadata Version must be 2")
        self.checks["chpe_metadata_v2"] = True
        _require(code_map != 0, "ARM64EC CodeMap RVA is zero")
        _require(0 < count <= _MAX_ENTRIES, "CodeMap count is zero or exceeds safety limit")
        _require(count <= (_U32_END - code_map) // 8,
                 "CodeMap count overflows RVA space")
        map_offset = self.rva(code_map, count * 8, "CodeMap entries")
        type_counts = {name: 0 for name in _TYPE_NAMES}
        sample = []
        for index in range(count):
            tagged_start, length = self.unpack("<II", map_offset + index * 8, "CodeMap entry")
            kind = tagged_start & 3
            start_rva = tagged_start & ~3
            _require(kind < len(_TYPE_NAMES), "CodeMap entry {} has unknown type 3".format(index))
            _require(length > 0, "CodeMap entry {} has zero length".format(index))
            self.rva(start_rva, length, "CodeMap entry {} code range".format(index))
            type_counts[_TYPE_NAMES[kind]] += 1
            if len(sample) < _SAMPLE_ENTRIES:
                sample.append({"index": index, "type": kind, "type_name": _TYPE_NAMES[kind],
                               "start_rva": start_rva, "length": length})
        self.evidence["code_map"] = {"rva": code_map, "file_offset": map_offset,
                                      "count": count, "type_counts": type_counts,
                                      "entries_sample": sample,
                                      "entries_sample_truncated": count > len(sample)}
        _require(type_counts["ARM64"] > 0, "CodeMap has no ARM64 (type 0) range")
        _require(type_counts["ARM64EC"] > 0, "CodeMap has no ARM64EC (type 1) range")
        self.checks["hybrid_code_map"] = True

    def relocations(self, dynamic_va, offset, section_index):
        if section_index:
            _require(section_index <= len(self.sections),
                     "DynamicValueRelocTableSection is outside the one-based section table")
            section = self.sections[section_index - 1]
            _require(offset <= section["raw_size"]
                     and 8 <= section["raw_size"] - offset,
                     "dynamic relocation table header exceeds its section's raw data")
            table_rva = section["rva"] + offset
            table = self.rva(table_rva, 8, "dynamic relocation table header")
            locator = "section_offset"
            if dynamic_va:
                _require(self.va_rva(dynamic_va, "DynamicValueRelocTable") == table_rva,
                         "dynamic relocation VA and section/offset locators disagree")
        else:
            _require(offset == 0, "dynamic relocation offset has no section index")
            _require(dynamic_va != 0, "dynamic relocation table locator is missing")
            table_rva = self.va_rva(dynamic_va, "DynamicValueRelocTable")
            table = self.rva(table_rva, 8, "dynamic relocation table header")
            locator = "va"
        version, payload_size = self.unpack("<II", table, "dynamic relocation table header")
        self.evidence["dynamic_relocations"] = {
            "rva": table_rva, "file_offset": table, "locator": locator,
            "version": version, "size": payload_size,
        }
        _require(version in (1, 2), "unsupported dynamic relocation table version")
        _require(payload_size > 0, "dynamic relocation table is empty")
        self.rva(table_rva, 8 + payload_size, "dynamic relocation table body")
        cursor, end = table + 8, table + 8 + payload_size
        entry_count = arm64x_count = arm64x_payload_bytes = 0
        symbols = set()
        samples = []
        while cursor < end:
            _require(entry_count < _MAX_ENTRIES, "dynamic relocation entry count exceeds safety limit")
            if version == 1:
                self.bounds(cursor, 12, "dynamic relocation v1 record", end)
                symbol, fixup_size = self.unpack("<QI", cursor, "dynamic relocation v1 record")
                header_size = 12
            else:
                self.bounds(cursor, 24, "dynamic relocation v2 record", end)
                header_size, fixup_size, symbol = self.unpack(
                    "<IIQ", cursor, "dynamic relocation v2 record")
                _require(header_size >= 24, "dynamic relocation v2 HeaderSize is smaller than 24")
            self.bounds(cursor, header_size, "dynamic relocation record header", end)
            self.bounds(cursor + header_size, fixup_size, "dynamic relocation fixup payload", end)
            if symbol == 6:
                _require(fixup_size > 0, "ARM64X dynamic relocation record has an empty fixup payload")
                arm64x_count += 1
                arm64x_payload_bytes += fixup_size
            symbols.add(symbol)
            if len(samples) < _SAMPLE_ENTRIES:
                samples.append({"file_offset": cursor, "symbol": symbol,
                                "header_size": header_size, "fixup_size": fixup_size})
            entry_count += 1
            cursor += header_size + fixup_size
        self.evidence["dynamic_relocations"].update({
            "entry_count": entry_count, "symbols": sorted(symbols),
            "arm64x_record_count": arm64x_count,
            "arm64x_fixup_bytes": arm64x_payload_bytes,
            "entries_sample": samples, "entries_sample_truncated": entry_count > len(samples),
        })
        _require(arm64x_count > 0, "dynamic relocations contain no ARM64X Symbol 6 record")
        self.checks["arm64x_dynamic_relocation"] = True

    def verify(self):
        metadata_va, dynamic_va, offset, section = self.headers()
        self.metadata(metadata_va)
        self.relocations(dynamic_va, offset, section)


def verify_hybrid_pe(path):
    """Return a JSON-compatible ARM64X structural-verification report.

    ``path`` accepts a string or text-valued ``os.PathLike``.  Success requires
    ARM64 COFF, PE32+, valid file-backed PE ranges, CHPE metadata v2, positive
    ARM64 and ARM64EC CodeMap ranges, and an entirely bounded DVRT (v1 or v2)
    containing an ARM64X Symbol 6 record with a nonempty fixup payload.  Either
    the one-based section/offset locator or the legacy VA locator is accepted.
    All records are checked, including records following the ARM64X one.

    Reports contain ``ok``, ``path``, ``errors`` (first failure), ``checks``
    (completed checks), and ``evidence`` (only data reached before a failure).
    Parsing stops on the first failure; false checks can mean not reached.
    Evidence samples are capped at 32 entries; counts cover all entries.
    """
    report = {
        "ok": False, "path": None, "errors": [],
        "checks": {name: False for name in (
            "arm64_machine", "pe32_plus", "pe_bounds", "load_config",
            "chpe_metadata_v2", "hybrid_code_map", "arm64x_dynamic_relocation")},
        "evidence": {},
    }
    try:
        path_text = os.fspath(path)
        _require(isinstance(path_text, str), "path must be a string or text-valued PathLike")
        report["path"] = path_text
        data = Path(path_text).read_bytes()
        report["evidence"]["file_size"] = len(data)
        _PE(data, report).verify()
        report["ok"] = True
    except (_InvalidPE, OSError, TypeError, ValueError, OverflowError, struct.error) as exc:
        report["errors"].append("{}: {}".format(type(exc).__name__, exc))
    return report
