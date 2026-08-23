from __future__ import annotations

import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from zipfile import ZipFile, is_zipfile

from tests.helpers import (
    FICTIONAL_EMAIL,
    FICTIONAL_NAME,
    FICTIONAL_SECRET,
    iter_png_chunks,
    write_docx,
    write_jpeg,
    write_pdf,
    write_png,
    write_pptx,
    write_traversal_zip,
    write_xlsx,
    write_zip_bomb,
)


class SyntheticHelperTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="sharelint-fixtures-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_fixture_identity_is_explicitly_non_routable_and_fictional(self) -> None:
        self.assertTrue(FICTIONAL_EMAIL.endswith("@example.invalid"))
        self.assertTrue(FICTIONAL_NAME.startswith("FICTITIOUS_"))
        self.assertEqual(FICTIONAL_SECRET, "ghp_" + ("A" * 36))

    def test_office_builders_emit_parseable_deterministic_opc(self) -> None:
        cases = [
            (
                write_docx,
                {"[Content_Types].xml", "word/document.xml", "docProps/core.xml"},
            ),
            (
                write_xlsx,
                {"[Content_Types].xml", "xl/workbook.xml", "xl/worksheets/sheet1.xml"},
            ),
            (
                write_pptx,
                {"[Content_Types].xml", "ppt/presentation.xml", "ppt/slides/slide1.xml"},
            ),
        ]
        for builder, required_members in cases:
            with self.subTest(builder=builder.__name__):
                first = builder(self.root / f"{builder.__name__}-first.office")
                second = builder(self.root / f"{builder.__name__}-second.office")
                self.assertEqual(first.read_bytes(), second.read_bytes())
                self.assertTrue(is_zipfile(first))
                with ZipFile(first) as archive:
                    self.assertLessEqual(required_members, set(archive.namelist()))
                    for name in archive.namelist():
                        if name.endswith(".xml") or name.endswith(".rels"):
                            ET.fromstring(archive.read(name))
                    all_xml = b"\n".join(
                        archive.read(name) for name in archive.namelist() if name.endswith(".xml")
                    )
                self.assertIn(FICTIONAL_NAME.encode(), all_xml)
                self.assertTrue(
                    b"example.invalid" in all_xml or FICTIONAL_SECRET.encode() in all_xml
                )

    def test_pdf_builder_emits_a_complete_minimal_pdf(self) -> None:
        payload = write_pdf(self.root / "fixture.pdf").read_bytes()

        self.assertTrue(payload.startswith(b"%PDF-1.4"))
        self.assertTrue(payload.rstrip().endswith(b"%%EOF"))
        self.assertIn(b"xref\n", payload)
        self.assertIn(b"/Info 6 0 R", payload)
        self.assertIn(FICTIONAL_NAME.encode(), payload)
        self.assertIn(FICTIONAL_SECRET.encode(), payload)

    def test_jpeg_builder_embeds_exif_without_external_dependencies(self) -> None:
        payload = write_jpeg(self.root / "fixture.jpg").read_bytes()

        self.assertTrue(payload.startswith(b"\xff\xd8\xff\xe1"))
        self.assertTrue(payload.endswith(b"\xff\xd9"))
        self.assertIn(b"Exif\x00\x00II*\x00", payload)
        self.assertIn(FICTIONAL_NAME.encode(), payload)
        self.assertIn(FICTIONAL_SECRET.encode(), payload)

    def test_png_builder_emits_crc_valid_metadata_chunks(self) -> None:
        chunks = list(iter_png_chunks(write_png(self.root / "fixture.png").read_bytes()))

        self.assertEqual(
            [kind for kind, _ in chunks],
            [b"IHDR", b"tEXt", b"tEXt", b"IDAT", b"IEND"],
        )
        metadata = b"\n".join(data for kind, data in chunks if kind == b"tEXt")
        self.assertIn(FICTIONAL_NAME.encode(), metadata)
        self.assertIn(FICTIONAL_SECRET.encode(), metadata)

    def test_adversarial_archives_are_small_and_purpose_built(self) -> None:
        traversal = write_traversal_zip(self.root / "traversal.zip")
        with ZipFile(traversal) as archive:
            names = archive.namelist()
        self.assertTrue(any("../" in name for name in names))
        self.assertTrue(any("..\\" in name for name in names))

        bomb = write_zip_bomb(self.root / "high-ratio.zip")
        self.assertLess(bomb.stat().st_size, 32 * 1024)
        with ZipFile(bomb) as archive:
            info = archive.infolist()[0]
        self.assertEqual(info.file_size, 8 * 1024 * 1024)
        self.assertGreater(info.file_size / info.compress_size, 500)


if __name__ == "__main__":
    unittest.main()
