"""Structural privacy checks for Office Open XML packages."""

from __future__ import annotations

import io
import re
import xml.etree.ElementTree as ET
from collections.abc import Mapping

from ..context import ScanContext
from ..models import SurfaceStatus

_TRACKED_RE = re.compile(rb"<(?:[A-Za-z_][\w.-]*:)?(?:ins|del|moveFrom|moveTo)\b")
_HIDDEN_TEXT_RE = re.compile(rb"<(?:[A-Za-z_][\w.-]*:)?vanish\b")
_HIDDEN_SLIDE_RE = re.compile(
    rb"<(?:[A-Za-z_][\w.-]*:)?sld\b[^>]*\bshow\s*=\s*['\"](?:0|false)['\"]", re.I
)
_TAG_RE = re.compile(r"<[^>]+>")
_UNSAFE_XML_DECLARATION_RE = re.compile(rb"<!\s*(?:DOCTYPE|ENTITY)\b", re.IGNORECASE)


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].rsplit(":", 1)[-1]


def _text_value(element: ET.Element) -> str:
    return " ".join("".join(element.itertext()).split())


def _xml_gap(
    source_chain: tuple[str, ...],
    context: ScanContext,
    size: int,
    *,
    limited: bool,
) -> None:
    if limited:
        context.add_finding(
            "SL.ARCHIVE.LIMIT_EXCEEDED",
            source_chain,
            "OOXML XML element count",
            "configured OOXML XML element count exceeded",
        )
        note = "XML element-count limit reached"
    else:
        context.add_error(
            source_chain,
            "SL.SCAN.READ_ERROR",
            "OOXML XML part could not be parsed safely",
        )
        note = "XML structure validation failed"
    context.add_surface(
        source_chain,
        "ooxml-xml",
        SurfaceStatus.PARTIAL,
        size,
        "ooxml",
        note,
    )


def _inspect_xml_part(
    name: str,
    data: bytes,
    source_chain: tuple[str, ...],
    context: ScanContext,
) -> None:
    """Parse one XML part as a bounded stream and retain no completed tree."""

    part_chain = source_chain + (context.display_path(name),)
    if _UNSAFE_XML_DECLARATION_RE.search(data):
        _xml_gap(part_chain, context, len(data), limited=False)
        return

    lowered = name.lower()
    custom_property_names: list[str] = []
    try:
        elements = ET.iterparse(io.BytesIO(data), events=("start", "end"))
        root: ET.Element | None = None
        element_count = 0
        for event, element in elements:
            if event == "start":
                element_count += 1
                if element_count > context.limits.max_xml_elements:
                    _xml_gap(part_chain, context, len(data), limited=True)
                    return
                if root is None:
                    root = element
                continue

            local_name = _local_name(element.tag)
            if lowered == "docprops/core.xml" and local_name in {
                "creator",
                "lastModifiedBy",
            }:
                value = _text_value(element)
                if value:
                    context.add_finding(
                        "SL.OFFICE.AUTHOR_METADATA",
                        part_chain,
                        local_name,
                        value,
                    )
            elif lowered == "docprops/app.xml" and local_name in {"Company", "Manager"}:
                value = _text_value(element)
                if value:
                    context.add_finding(
                        "SL.OFFICE.ORGANIZATION_METADATA",
                        part_chain,
                        local_name,
                        value,
                    )
            elif lowered == "docprops/custom.xml" and local_name == "property":
                if len(custom_property_names) < 20:
                    custom_property_names.append(element.attrib.get("name", "unnamed"))
            elif lowered.endswith(".rels"):
                if element.attrib.get("TargetMode", "").lower() == "external":
                    target = element.attrib.get("Target", "external relationship")
                    context.add_finding(
                        "SL.OFFICE.EXTERNAL_RELATIONSHIP",
                        part_chain,
                        "relationship target",
                        target,
                        evidence_kind="path",
                    )
            elif lowered == "xl/workbook.xml" and local_name == "sheet":
                state = element.attrib.get("state", "visible").lower()
                if state in {"hidden", "veryhidden"}:
                    sheet_name = element.attrib.get("name", "unnamed sheet")
                    context.add_finding(
                        "SL.OFFICE.HIDDEN_SHEET",
                        part_chain,
                        f"sheet state={state}",
                        sheet_name,
                    )
            element.clear()
            if root is not None and element is not root:
                root.clear()
    except (ET.ParseError, LookupError, ValueError):
        _xml_gap(part_chain, context, len(data), limited=False)
        return

    if lowered == "docprops/custom.xml":
        context.add_finding(
            "SL.OFFICE.CUSTOM_PROPERTIES",
            part_chain,
            "custom properties",
            ", ".join(custom_property_names) or "custom property payload",
        )


def detect_office_kind(names: set[str]) -> str | None:
    if "word/document.xml" in names:
        return "docx"
    if "xl/workbook.xml" in names:
        return "xlsx"
    if "ppt/presentation.xml" in names:
        return "pptx"
    return None


def inspect_ooxml(
    members: Mapping[str, bytes],
    source_chain: tuple[str, ...],
    context: ScanContext,
) -> str | None:
    names = set(members)
    office_kind = detect_office_kind(names)
    if office_kind is None:
        return None

    for name in sorted(names):
        lowered = name.lower()
        if not (lowered.endswith(".xml") or lowered.endswith(".rels")):
            continue
        _inspect_xml_part(name, members[name], source_chain, context)

    for name, data in members.items():
        lowered = name.lower()
        part_chain = source_chain + (context.display_path(name),)

        if (
            (lowered.startswith("word/") and "/comments" in lowered)
            or (lowered.startswith("xl/") and "/comments" in lowered)
            or (lowered.startswith("ppt/") and "/comments" in lowered)
        ) and lowered.endswith(".xml"):
            context.add_finding(
                "SL.OFFICE.COMMENTS",
                part_chain,
                "package part",
                name,
            )

        if lowered.startswith("word/") and lowered.endswith(".xml"):
            if _TRACKED_RE.search(data):
                context.add_finding(
                    "SL.OFFICE.TRACKED_CHANGES",
                    part_chain,
                    "XML revision markup",
                    name,
                )
            if _HIDDEN_TEXT_RE.search(data):
                context.add_finding(
                    "SL.OFFICE.HIDDEN_TEXT",
                    part_chain,
                    "XML hidden-text property",
                    name,
                )

        if lowered.startswith("ppt/notesslides/") and lowered.endswith(".xml"):
            visible = " ".join(_TAG_RE.sub(" ", data.decode("utf-8", errors="ignore")).split())
            if visible:
                context.add_finding(
                    "SL.OFFICE.NOTES",
                    part_chain,
                    "speaker notes part",
                    name,
                )

        if (
            lowered.startswith("ppt/slides/slide")
            and lowered.endswith(".xml")
            and _HIDDEN_SLIDE_RE.search(data[:4096])
        ):
            context.add_finding(
                "SL.OFFICE.HIDDEN_SLIDE",
                part_chain,
                "slide visibility",
                name,
            )

        if "/embeddings/" in lowered and not lowered.endswith("/"):
            context.add_finding(
                "SL.OFFICE.EMBEDDED_OBJECT",
                part_chain,
                "package part",
                name,
            )
        if lowered.endswith("vbaproject.bin"):
            context.add_finding("SL.OFFICE.MACRO", part_chain, "package part", name)
        if lowered.startswith("customxml/item") and lowered.endswith(".xml"):
            context.add_finding("SL.OFFICE.CUSTOM_XML", part_chain, "package part", name)
        if lowered.startswith("docprops/thumbnail."):
            context.add_finding("SL.OFFICE.THUMBNAIL", part_chain, "package part", name)
        if "/printersettings/" in lowered:
            context.add_finding(
                "SL.OFFICE.PRINTER_SETTINGS",
                part_chain,
                "package part",
                name,
            )

    return office_kind
