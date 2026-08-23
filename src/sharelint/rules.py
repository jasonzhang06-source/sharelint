"""Rule registry. Rule identifiers are a public compatibility contract."""

from __future__ import annotations

from dataclasses import dataclass

from .models import Severity


@dataclass(frozen=True, slots=True)
class Rule:
    rule_id: str
    title: str
    severity: Severity
    remediation: str
    tags: tuple[str, ...]


def _rule(
    rule_id: str,
    title: str,
    severity: Severity,
    remediation: str,
    *tags: str,
) -> Rule:
    return Rule(rule_id, title, severity, remediation, tuple(tags))


RULES: dict[str, Rule] = {
    rule.rule_id: rule
    for rule in [
        _rule(
            "SL.SECRET.PRIVATE_KEY",
            "Private key material",
            Severity.CRITICAL,
            "Remove the key, rotate it, and share only its public counterpart if required.",
            "secret",
            "text",
        ),
        _rule(
            "SL.SECRET.AWS_ACCESS_KEY",
            "AWS access key identifier",
            Severity.CRITICAL,
            "Remove and rotate the credential before sharing the bundle.",
            "secret",
            "text",
        ),
        _rule(
            "SL.SECRET.GITHUB_TOKEN",
            "GitHub token",
            Severity.CRITICAL,
            "Remove and revoke the token before sharing the bundle.",
            "secret",
            "text",
        ),
        _rule(
            "SL.SECRET.JWT",
            "JSON Web Token",
            Severity.CRITICAL,
            "Remove and revoke the token if it can still authorize requests.",
            "secret",
            "text",
        ),
        _rule(
            "SL.SECRET.GENERIC_ASSIGNMENT",
            "Likely assigned secret",
            Severity.HIGH,
            "Replace the value with a documented placeholder and rotate it if it was live.",
            "secret",
            "text",
        ),
        _rule(
            "SL.PII.EMAIL",
            "Email address",
            Severity.MEDIUM,
            "Confirm the address is intended for the recipient or replace it with a placeholder.",
            "pii",
            "text",
        ),
        _rule(
            "SL.PII.US_SSN",
            "US Social Security number pattern",
            Severity.HIGH,
            "Remove or irreversibly redact the identifier before sharing.",
            "pii",
            "text",
        ),
        _rule(
            "SL.PII.PAYMENT_CARD",
            "Payment card number",
            Severity.HIGH,
            "Remove or irreversibly redact the number before sharing.",
            "pii",
            "text",
        ),
        _rule(
            "SL.PATH.LOCAL_HOME",
            "Local home-directory path",
            Severity.MEDIUM,
            "Replace machine-specific absolute paths with portable relative paths.",
            "path",
            "identity",
        ),
        _rule(
            "SL.PATH.EMAIL_IN_NAME",
            "Email address in a file or directory name",
            Severity.HIGH,
            "Rename the item before sharing it.",
            "path",
            "pii",
        ),
        _rule(
            "SL.PATH.SENSITIVE_LABEL",
            "Potentially sensitive label in a path",
            Severity.LOW,
            "Review whether the path name itself reveals confidential context.",
            "path",
        ),
        _rule(
            "SL.ARCHIVE.PATH_TRAVERSAL",
            "Unsafe archive member path",
            Severity.CRITICAL,
            "Rebuild the archive without absolute paths or parent-directory traversal.",
            "archive",
            "integrity",
        ),
        _rule(
            "SL.ARCHIVE.SYMLINK",
            "Symbolic link in share boundary",
            Severity.HIGH,
            "Replace the link with an intentional regular file inside the share boundary.",
            "archive",
            "coverage",
        ),
        _rule(
            "SL.ARCHIVE.DUPLICATE_PATH",
            "Duplicate archive member path",
            Severity.HIGH,
            "Rebuild the archive with one unambiguous entry per normalized path.",
            "archive",
            "integrity",
        ),
        _rule(
            "SL.ARCHIVE.ENCRYPTED_MEMBER",
            "Encrypted archive member",
            Severity.HIGH,
            "Decrypt and rescan the content locally, or exclude it from the share bundle.",
            "archive",
            "coverage",
        ),
        _rule(
            "SL.ARCHIVE.LIMIT_EXCEEDED",
            "Archive safety limit exceeded",
            Severity.HIGH,
            "Reduce or split the archive, then scan again without raising safety limits blindly.",
            "archive",
            "coverage",
        ),
        _rule(
            "SL.OFFICE.AUTHOR_METADATA",
            "Office author metadata",
            Severity.MEDIUM,
            "Remove creator and last-modified-by properties in the source application.",
            "office",
            "metadata",
        ),
        _rule(
            "SL.OFFICE.ORGANIZATION_METADATA",
            "Office organization metadata",
            Severity.MEDIUM,
            "Remove company, manager, and organization properties before export.",
            "office",
            "metadata",
        ),
        _rule(
            "SL.OFFICE.CUSTOM_PROPERTIES",
            "Office custom properties",
            Severity.MEDIUM,
            "Review and remove custom document properties before export.",
            "office",
            "metadata",
        ),
        _rule(
            "SL.OFFICE.COMMENTS",
            "Office comments or review annotations",
            Severity.HIGH,
            "Resolve and remove comments in the source application, then export again.",
            "office",
            "hidden-content",
        ),
        _rule(
            "SL.OFFICE.TRACKED_CHANGES",
            "Tracked or deleted Office content",
            Severity.HIGH,
            "Accept or reject all revisions intentionally, then remove revision history.",
            "office",
            "hidden-content",
        ),
        _rule(
            "SL.OFFICE.HIDDEN_TEXT",
            "Hidden Word text",
            Severity.HIGH,
            "Unhide, review, and either remove or intentionally include the text.",
            "office",
            "hidden-content",
        ),
        _rule(
            "SL.OFFICE.HIDDEN_SHEET",
            "Hidden spreadsheet sheet",
            Severity.HIGH,
            "Unhide and review the sheet, or remove it from a share-specific copy.",
            "office",
            "hidden-content",
        ),
        _rule(
            "SL.OFFICE.NOTES",
            "PowerPoint speaker notes",
            Severity.HIGH,
            "Review and remove speaker notes from a share-specific copy.",
            "office",
            "hidden-content",
        ),
        _rule(
            "SL.OFFICE.HIDDEN_SLIDE",
            "Hidden PowerPoint slide",
            Severity.HIGH,
            "Unhide and review the slide, or remove it from a share-specific copy.",
            "office",
            "hidden-content",
        ),
        _rule(
            "SL.OFFICE.EXTERNAL_RELATIONSHIP",
            "External Office relationship",
            Severity.HIGH,
            "Break or intentionally document links to external files and URLs.",
            "office",
            "external-reference",
        ),
        _rule(
            "SL.OFFICE.EMBEDDED_OBJECT",
            "Embedded Office object",
            Severity.HIGH,
            "Extract, review, and scan the embedded object or remove it.",
            "office",
            "embedded-content",
        ),
        _rule(
            "SL.OFFICE.MACRO",
            "Office macro project",
            Severity.CRITICAL,
            "Use a macro-free share copy unless the recipient explicitly requires reviewed macros.",
            "office",
            "active-content",
        ),
        _rule(
            "SL.OFFICE.CUSTOM_XML",
            "Office custom XML payload",
            Severity.MEDIUM,
            "Review or remove custom XML parts that are not required by the shared document.",
            "office",
            "hidden-content",
        ),
        _rule(
            "SL.OFFICE.THUMBNAIL",
            "Office preview thumbnail",
            Severity.LOW,
            "Regenerate or remove the thumbnail if it can reveal an earlier document state.",
            "office",
            "metadata",
        ),
        _rule(
            "SL.OFFICE.PRINTER_SETTINGS",
            "Office printer settings",
            Severity.LOW,
            "Remove cached printer settings if device or organization details are sensitive.",
            "office",
            "metadata",
        ),
        _rule(
            "SL.PDF.AUTHOR_METADATA",
            "PDF author metadata",
            Severity.MEDIUM,
            "Remove the PDF Info/XMP author fields and rescan the exported document.",
            "pdf",
            "metadata",
        ),
        _rule(
            "SL.PDF.SOFTWARE_METADATA",
            "PDF creator or producer metadata",
            Severity.LOW,
            "Remove software-identifying metadata if the authoring environment is sensitive.",
            "pdf",
            "metadata",
        ),
        _rule(
            "SL.PDF.ACTIVE_CONTENT",
            "PDF active content",
            Severity.CRITICAL,
            "Remove JavaScript, launch actions, rich media, and automatic open actions.",
            "pdf",
            "active-content",
        ),
        _rule(
            "SL.PDF.EMBEDDED_FILE",
            "PDF embedded file",
            Severity.HIGH,
            "Extract and scan the attachment or remove it from a share-specific PDF.",
            "pdf",
            "embedded-content",
        ),
        _rule(
            "SL.PDF.ENCRYPTED",
            "Encrypted PDF content",
            Severity.HIGH,
            "Decrypt the PDF locally and rescan it before sharing.",
            "pdf",
            "coverage",
        ),
        _rule(
            "SL.PDF.INCREMENTAL_HISTORY",
            "PDF incremental revision history",
            Severity.MEDIUM,
            "Rewrite the PDF from a reviewed source to discard prior incremental revisions.",
            "pdf",
            "hidden-content",
        ),
        _rule(
            "SL.IMAGE.GPS_METADATA",
            "Image GPS metadata",
            Severity.HIGH,
            "Remove location metadata or export a metadata-free copy before sharing.",
            "image",
            "metadata",
            "location",
        ),
        _rule(
            "SL.IMAGE.IDENTITY_METADATA",
            "Image identity metadata",
            Severity.MEDIUM,
            "Remove artist, copyright, owner, or author fields before sharing.",
            "image",
            "metadata",
        ),
        _rule(
            "SL.IMAGE.DEVICE_METADATA",
            "Image device metadata",
            Severity.LOW,
            "Remove camera, phone, lens, and software fields if device fingerprinting matters.",
            "image",
            "metadata",
        ),
        _rule(
            "SL.IMAGE.TEXT_METADATA",
            "Image text metadata",
            Severity.MEDIUM,
            "Review and remove free-form image descriptions, comments, and XMP fields.",
            "image",
            "metadata",
        ),
        _rule(
            "SL.SCAN.UNSUPPORTED_CONTENT",
            "Unsupported content surface",
            Severity.INFO,
            "Review the content manually or add a trusted scanner before strict packing.",
            "coverage",
        ),
        _rule(
            "SL.SCAN.READ_ERROR",
            "Content could not be inspected",
            Severity.HIGH,
            "Resolve the read or parser error and run ShareLint again.",
            "coverage",
        ),
    ]
}


def get_rule(rule_id: str) -> Rule:
    try:
        return RULES[rule_id]
    except KeyError as exc:
        raise KeyError(f"unknown ShareLint rule: {rule_id}") from exc
