from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile
from xml.sax.saxutils import escape
import re
import sys


W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
R_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"


def xml_escape(value: str) -> str:
    return escape(value, {'"': "&quot;"})


def run(text: str, style: str | None = None, bold: bool = False) -> str:
    props = []
    if style == "code":
        props.append('<w:rStyle w:val="CodeChar"/>')
    if bold:
        props.append("<w:b/>")
    rpr = f"<w:rPr>{''.join(props)}</w:rPr>" if props else ""
    preserve = ' xml:space="preserve"' if text.startswith(" ") or text.endswith(" ") else ""
    return f"<w:r>{rpr}<w:t{preserve}>{xml_escape(text)}</w:t></w:r>"


def para(
    text: str = "",
    style: str | None = None,
    bullet: bool = False,
    code: bool = False,
    center: bool = False,
    pagebreak: bool = False,
) -> str:
    if pagebreak:
        return '<w:p><w:r><w:br w:type="page"/></w:r></w:p>'

    props = []
    if style:
        props.append(f'<w:pStyle w:val="{style}"/>')
    if bullet:
        props.append('<w:ind w:left="720" w:hanging="360"/>')
    if center:
        props.append('<w:jc w:val="center"/>')
    if code:
        props.append('<w:pStyle w:val="CodeBlock"/>')
    ppr = f"<w:pPr>{''.join(props)}</w:pPr>" if props else ""
    if bullet:
        text = "• " + text
    return f"<w:p>{ppr}{run(text, style='code' if code else None)}</w:p>"


def convert(md_path: Path, docx_path: Path) -> None:
    content = md_path.read_text(encoding="utf-8")
    body: list[str] = []
    in_code = False
    code_lines: list[str] = []

    for raw in content.splitlines():
        line = raw.rstrip()

        if line.strip() == r"\pagebreak":
            body.append(para(pagebreak=True))
            continue

        if line.startswith("```"):
            if not in_code:
                in_code = True
                code_lines = []
            else:
                for code_line in code_lines:
                    body.append(para(code_line if code_line else " ", code=True))
                in_code = False
            continue

        if in_code:
            code_lines.append(line)
            continue

        if not line.strip():
            body.append(para())
            continue

        heading = re.match(r"^(#{1,6})\s+(.*)$", line)
        if heading:
            level = len(heading.group(1))
            title = heading.group(2)
            if title in {
                "EKONOMSKA ŠOLA MURSKA SOBOTA",
                "VIŠJA STROKOVNA ŠOLA",
                "DIPLOMSKA NALOGA",
                "NetSentinel IDS: prototipni sistem za zaznavanje in obravnavo omrežnih groženj",
            }:
                body.append(para(title, style="Title" if title == "DIPLOMSKA NALOGA" else "Subtitle", center=True))
            else:
                body.append(para(title, style=f"Heading{min(level, 4)}"))
            continue

        if line.startswith("- "):
            body.append(para(line[2:], bullet=True))
            continue

        if re.match(r"^\d+\.\s+", line):
            body.append(para(line))
            continue

        if line.startswith("[VSTAVI") or line.startswith("[V WORDU") or line.startswith("[VSE VIRE") or line.startswith("[DOPOLNI"):
            body.append(para(line, style="Placeholder"))
            continue

        clean = re.sub(r"`([^`]*)`", r"\1", line)
        body.append(para(clean))

    section = (
        '<w:sectPr>'
        '<w:pgSz w:w="11906" w:h="16838"/>'
        '<w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1701" w:header="720" w:footer="720" w:gutter="0"/>'
        "</w:sectPr>"
    )
    document_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<w:document xmlns:w="{W_NS}" xmlns:r="{R_NS}"><w:body>{"".join(body)}{section}</w:body></w:document>'
    )
    styles_xml = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="{W_NS}">
<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/><w:qFormat/><w:rPr><w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman"/><w:sz w:val="24"/><w:lang w:val="sl-SI"/></w:rPr><w:pPr><w:jc w:val="both"/><w:spacing w:before="0" w:after="200" w:line="360" w:lineRule="auto"/></w:pPr></w:style>
<w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:basedOn w:val="Normal"/><w:qFormat/><w:rPr><w:b/><w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman"/><w:sz w:val="38"/></w:rPr><w:pPr><w:jc w:val="center"/><w:spacing w:before="480" w:after="360" w:line="360" w:lineRule="auto"/></w:pPr></w:style>
<w:style w:type="paragraph" w:styleId="Subtitle"><w:name w:val="Subtitle"/><w:basedOn w:val="Normal"/><w:qFormat/><w:rPr><w:b/><w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman"/><w:sz w:val="28"/></w:rPr><w:pPr><w:jc w:val="center"/><w:spacing w:before="120" w:after="240" w:line="360" w:lineRule="auto"/></w:pPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/><w:rPr><w:b/><w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman"/><w:sz w:val="32"/></w:rPr><w:pPr><w:keepNext/><w:spacing w:before="520" w:after="240" w:line="360" w:lineRule="auto"/></w:pPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/><w:rPr><w:b/><w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman"/><w:sz w:val="28"/></w:rPr><w:pPr><w:keepNext/><w:spacing w:before="360" w:after="180" w:line="360" w:lineRule="auto"/></w:pPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading3"><w:name w:val="heading 3"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/><w:rPr><w:b/><w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman"/><w:sz w:val="26"/></w:rPr><w:pPr><w:keepNext/><w:spacing w:before="280" w:after="160" w:line="360" w:lineRule="auto"/></w:pPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading4"><w:name w:val="heading 4"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/><w:rPr><w:b/><w:i/><w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman"/><w:sz w:val="24"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Placeholder"><w:name w:val="Placeholder"/><w:basedOn w:val="Normal"/><w:rPr><w:b/><w:color w:val="C00000"/><w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman"/><w:sz w:val="22"/></w:rPr><w:pPr><w:jc w:val="both"/><w:spacing w:before="180" w:after="220" w:line="300" w:lineRule="auto"/><w:shd w:val="clear" w:color="auto" w:fill="FFF2CC"/></w:pPr></w:style>
<w:style w:type="paragraph" w:styleId="CodeBlock"><w:name w:val="Code Block"/><w:basedOn w:val="Normal"/><w:rPr><w:rFonts w:ascii="Consolas" w:hAnsi="Consolas"/><w:sz w:val="20"/></w:rPr><w:pPr><w:jc w:val="left"/><w:spacing w:after="60" w:line="240" w:lineRule="auto"/></w:pPr></w:style>
<w:style w:type="character" w:styleId="CodeChar"><w:name w:val="Code Char"/><w:rPr><w:rFonts w:ascii="Consolas" w:hAnsi="Consolas"/><w:sz w:val="20"/></w:rPr></w:style>
</w:styles>'''
    content_types = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/></Types>'''
    rels = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>'''
    doc_rels = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>'''

    if docx_path.exists():
        docx_path.unlink()
    with ZipFile(docx_path, "w", ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", content_types)
        archive.writestr("_rels/.rels", rels)
        archive.writestr("word/_rels/document.xml.rels", doc_rels)
        archive.writestr("word/document.xml", document_xml)
        archive.writestr("word/styles.xml", styles_xml)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("Usage: md_to_thesis_docx.py input.md output.docx")
    convert(Path(sys.argv[1]), Path(sys.argv[2]))
