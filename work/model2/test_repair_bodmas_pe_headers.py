import importlib.util
import struct
import sys
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("repair_bodmas_pe_headers.py")
SPEC = importlib.util.spec_from_file_location("repair_bodmas", MODULE_PATH)
assert SPEC and SPEC.loader
repair = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = repair
SPEC.loader.exec_module(repair)


def synthetic_pe(optional_magic: int, machine: int = 0, subsystem: int = 0) -> bytes:
    pe_offset = 0x80
    optional_size = 0xE0 if optional_magic == repair.PE32_MAGIC else 0xF0
    data = bytearray(pe_offset + 24 + optional_size)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, pe_offset)
    data[pe_offset : pe_offset + 4] = b"PE\0\0"
    struct.pack_into("<H", data, pe_offset + 4, machine)
    struct.pack_into("<H", data, pe_offset + 6, 3)
    struct.pack_into("<H", data, pe_offset + 20, optional_size)
    struct.pack_into("<H", data, pe_offset + 24, optional_magic)
    struct.pack_into("<H", data, pe_offset + 24 + 68, subsystem)
    return bytes(data)


class RepairBodmasTests(unittest.TestCase):
    def inspect(self, content: bytes):
        path = MODULE_PATH.with_name("_synthetic_pe_test.bin")
        try:
            path.write_bytes(content)
            return repair.inspect_pe(path)
        finally:
            path.unlink(missing_ok=True)

    def test_infers_x86_from_pe32(self):
        header = self.inspect(synthetic_pe(repair.PE32_MAGIC))
        self.assertEqual(header.machine, 0)
        self.assertEqual(header.inferred_machine, repair.IMAGE_FILE_MACHINE_I386)
        self.assertEqual(header.pe_kind, "PE32")

    def test_infers_x64_from_pe32_plus(self):
        header = self.inspect(synthetic_pe(repair.PE32_PLUS_MAGIC))
        self.assertEqual(header.inferred_machine, repair.IMAGE_FILE_MACHINE_AMD64)
        self.assertEqual(header.pe_kind, "PE32+")

    def test_preserves_existing_subsystem(self):
        header = self.inspect(synthetic_pe(repair.PE32_MAGIC, subsystem=3))
        self.assertEqual(header.subsystem, 3)

    def test_rejects_non_pe(self):
        with self.assertRaises(repair.PEFormatError):
            self.inspect(bytes(512))

    def test_batch_spec(self):
        self.assertEqual(
            repair.parse_batch_spec("1-3,batch_5"),
            {"batch_1", "batch_2", "batch_3", "batch_5"},
        )


if __name__ == "__main__":
    unittest.main()
