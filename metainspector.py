#!/usr/bin/env python3
import argparse
import grp
import hashlib
import json
import os
import pwd
import re
import stat
import sys
import zipfile
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

from PIL import ExifTags, Image
from pypdf import PdfReader, PdfWriter
from rich.console import Console
from rich.panel import Panel
from rich.tree import Tree

console = Console()

# Firmas hexadecimales (Magic Bytes) principales
MAGIC_SIGNATURES = [
    (b"%PDF-", "PDF", {".pdf"}),
    (b"\xff\xd8\xff", "JPEG", {".jpg", ".jpeg"}),
    (b"\x89PNG\r\n\x1a\n", "PNG", {".png"}),
    (b"GIF87a", "GIF", {".gif"}),
    (b"GIF89a", "GIF", {".gif"}),
    (b"PK\x03\x04", "ZIP / Office / OpenDocument", {
        ".zip", ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp", ".jar", ".apk"
    }),
    (b"\x7fELF", "ELF (Ejecutable Linux)", {"", ".elf", ".bin", ".so"}),
    (b"MZ", "PE/EXE (Ejecutable Windows)", {".exe", ".dll", ".sys"}),
]

PDF_RISK_TAGS = [
    b"/JavaScript", b"/JS", b"/OpenAction", b"/AA",
    b"/Launch", b"/EmbeddedFile", b"/URI", b"/RichMedia"
]


def fmt_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def parse_any_date(value: str):
    """Normaliza fechas EXIF, PDF (D:YYYYMMDD...) e ISO para detectar anomalías."""
    if not value or not isinstance(value, str):
        return None
    s = value.strip()
    # Formato PDF: D:20261116103000...
    m_pdf = re.match(r"D:(\d{4})(\d{2})(\d{2})(\d{2})?(\d{2})?(\d{2})?", s)
    if m_pdf:
        y, mo, d = int(m_pdf.group(1)), int(m_pdf.group(2)), int(m_pdf.group(3))
        hh = int(m_pdf.group(4) or 0)
        mm = int(m_pdf.group(5) or 0)
        ss = int(m_pdf.group(6) or 0)
        try:
            return datetime(y, mo, d, hh, mm, ss)
        except ValueError:
            return None
    # Formatos EXIF e ISO
    for fmt in ("%Y:%m:%d %H:%M:%S", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(s[:19], fmt)
        except ValueError:
            continue
    return None


def get_hashes_and_magic(path: Path) -> dict:
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    header = b""

    with path.open("rb") as f:
        header = f.read(16)
        md5.update(header)
        sha256.update(header)
        while chunk := f.read(65536):
            md5.update(chunk)
            sha256.update(chunk)

    detected_type = "Desconocido / Texto plano"
    expected_exts = None
    for sig, name, exts in MAGIC_SIGNATURES:
        if header.startswith(sig):
            detected_type = name
            expected_exts = exts
            break

    mismatch = False
    if expected_exts is not None and path.suffix.lower() not in expected_exts:
        mismatch = True

    return {
        "magic_hex": " ".join(f"{b:02X}" for b in header[:8]),
        "detected_type": detected_type,
        "extension_mismatch": mismatch,
        "md5": md5.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


def get_linux_fs_metadata(path: Path) -> dict:
    st = path.stat()
    try:
        user = pwd.getpwuid(st.st_uid).pw_name
    except KeyError:
        user = str(st.st_uid)
    try:
        group = grp.getgrgid(st.st_gid).gr_name
    except KeyError:
        group = str(st.st_gid)

    return {
        "yellow": {
            "Nombre de archivo": path.name,
            "Permisos": stat.filemode(st.st_mode),
            "UID / GID": f"{st.st_uid} ({user}) : {st.st_gid} ({group})",
            "Modify (mtime)": fmt_ts(st.st_mtime),
            "Access (atime)": fmt_ts(st.st_atime),
        },
        "red": {
            "Inodo": str(st.st_ino),
            "Change (ctime)": fmt_ts(st.st_ctime),
            "Tamaño (FileSize)": f"{st.st_size} bytes ({st.st_size / 1024:.2f} KiB)",
        },
    }


def rational_to_deg(values) -> float:
    d, m, s = [float(v) for v in values]
    return d + (m / 60.0) + (s / 3600.0)


def extract_image_metadata(path: Path) -> dict:
    meta = {}
    with Image.open(path) as img:
        meta["Dimensiones"] = f"{img.width}x{img.height} ({img.format}, modo {img.mode})"
        exif = img.getexif()
        if not exif:
            return meta

        # IFD principal (Make, Model, Software, DateTime...)
        for tag_id, val in exif.items():
            tag = ExifTags.TAGS.get(tag_id, str(tag_id))
            if isinstance(val, bytes):
                val = val.decode("utf-8", errors="ignore").strip("\x00")
            meta[tag] = str(val)[:120]

        # Sub-IFD EXIF (DateTimeOriginal, LensModel, ISO...)
        exif_sub = exif.get_ifd(0x8769)
        for tag_id, val in exif_sub.items():
            tag = ExifTags.TAGS.get(tag_id, str(tag_id))
            if tag in ("MakerNote", "UserComment") and isinstance(val, bytes):
                continue
            if isinstance(val, bytes):
                val = val.decode("utf-8", errors="ignore").strip("\x00")
            meta[tag] = str(val)[:120]

        # Sub-IFD GPS
        gps_ifd = exif.get_ifd(0x8825)
        if gps_ifd:
            gps = {ExifTags.GPSTAGS.get(k, str(k)): v for k, v in gps_ifd.items()}
            if "GPSLatitude" in gps and "GPSLongitude" in gps:
                try:
                    lat = rational_to_deg(gps["GPSLatitude"])
                    if gps.get("GPSLatitudeRef") == "S":
                        lat = -lat
                    lon = rational_to_deg(gps["GPSLongitude"])
                    if gps.get("GPSLongitudeRef") == "W":
                        lon = -lon
                    meta["GPS Position"] = f"{lat:.6f}, {lon:.6f}"
                    meta["GPS Google Maps"] = f"https://www.google.com/maps?q={lat:.6f},{lon:.6f}"
                except Exception:
                    meta["GPS Raw"] = str(gps)
            if "GPSAltitude" in gps:
                meta["GPS Altitude"] = f"{float(gps['GPSAltitude']):.2f} m"
    return meta


def extract_pdf_metadata(path: Path) -> tuple[dict, list[str]]:
    meta = {}
    alerts = []
    reader = PdfReader(str(path))
    meta["Páginas"] = str(len(reader.pages))
    meta["Cifrado"] = "Sí" if reader.is_encrypted else "No"

    # 1. Diccionario clásico /Info
    if reader.metadata:
        for k, v in reader.metadata.items():
            clean_key = k.lstrip("/")
            meta[f"Info:{clean_key}"] = str(v)

    # 2. Metadatos XML / XMP
    try:
        xmp = reader.xmp_metadata
        if xmp:
            if xmp.dc_creator:
                meta["XMP:Creator"] = ", ".join(xmp.dc_creator)
            if xmp.xmp_creator_tool:
                meta["XMP:CreatorTool"] = str(xmp.xmp_creator_tool)
            if xmp.pdf_producer:
                meta["XMP:Producer"] = str(xmp.pdf_producer)
            if xmp.xmp_create_date:
                meta["XMP:CreateDate"] = str(xmp.xmp_create_date)
            if xmp.xmp_modify_date:
                meta["XMP:ModifyDate"] = str(xmp.xmp_modify_date)
    except Exception:
        pass

    # 3. Escaneo rápido de etiquetas PDF de riesgo (estilo pdfid)
    raw = path.read_bytes()
    found_tags = [tag.decode() for tag in PDF_RISK_TAGS if tag in raw]
    if found_tags:
        alerts.append(f"Indicadores interactivos/riesgo en PDF detectados: {', '.join(found_tags)}")

    return meta, alerts


def extract_zip_xml_metadata(path: Path) -> dict:
    """Extrae metadatos de MS Office (.docx/.xlsx/.pptx) y OpenOffice (.odt/.ods/.odp)."""
    meta = {}
    targets = ["docProps/core.xml", "docProps/app.xml", "meta.xml"]
    with zipfile.ZipFile(path, "r") as zf:
        names = set(zf.namelist())
        for target in targets:
            if target in names:
                xml_data = zf.read(target)
                root = ET.fromstring(xml_data)
                for elem in root.iter():
                    tag = elem.tag.split("}")[-1]
                    text = (elem.text or "").strip()
                    if text:
                        meta[f"{Path(target).stem}:{tag}"] = text
        # Aviso si existen comentarios internos en Word
        if "word/comments.xml" in names:
            meta["Aviso Interno"] = "Contiene archivo de comentarios (word/comments.xml)"
    return meta


def detect_temporal_anomalies(internal_meta: dict) -> list[str]:
    alerts = []
    create_keys = ["CreateDate", "DateTimeOriginal", "Info:CreationDate", "XMP:CreateDate", "core:created", "meta:creation-date"]
    modify_keys = ["DateTime", "ModifyDate", "Info:ModDate", "XMP:ModifyDate", "core:modified", "meta:date"]

    c_date = next((parse_any_date(internal_meta[k]) for k in create_keys if k in internal_meta), None)
    m_date = next((parse_any_date(internal_meta[k]) for k in modify_keys if k in internal_meta), None)

    if c_date and m_date and m_date < c_date:
        alerts.append(
            f"Anomalía temporal: fecha de modificación ({m_date}) anterior a creación ({c_date}). Posible manipulación."
        )
    return alerts


def strip_metadata(path: Path) -> Path:
    """Crea una copia limpia del archivo sin metadatos internos."""
    out_path = path.with_name(f"{path.stem}_clean{path.suffix}")
    ext = path.suffix.lower()

    if ext in {".jpg", ".jpeg", ".png", ".webp", ".tiff"}:
        with Image.open(path) as img:
            clean_img = img.convert("RGB") if ext in {".jpg", ".jpeg"} and img.mode not in {"RGB", "L"} else img
            # Reconstruye solo los píxeles descartando EXIF, XMP, IPTC y miniaturas
            stripped = Image.frombytes(clean_img.mode, clean_img.size, clean_img.tobytes())
            stripped.save(out_path)
        return out_path

    if ext == ".pdf":
        reader = PdfReader(str(path))
        writer = PdfWriter()
        for page in reader.pages:
            writer.add_page(page)
        # Limpia diccionario /Info (al copiar solo páginas no se hereda el XMP original)
        writer.add_metadata({"/Producer": "", "/Creator": "", "/Author": "", "/Title": "", "/Subject": ""})
        with out_path.open("wb") as f:
            writer.write(f)
        return out_path

    if ext in {".odt", ".ods", ".odp", ".docx", ".xlsx", ".pptx"}:
        xml_targets = {"meta.xml", "docProps/core.xml", "docProps/app.xml"}
        with zipfile.ZipFile(path, "r") as zin, zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as zout:
            for item in zin.infolist():
                if item.filename in xml_targets:
                    # En ODT se puede omitir meta.xml; en Office vaciamos los valores de texto del XML
                    if ext.startswith(".od"):
                        continue
                    root = ET.fromstring(zin.read(item.filename))
                    for elem in root.iter():
                        if elem.text and elem.text.strip():
                            elem.text = ""
                    zout.writestr(item, ET.tostring(root, encoding="utf-8", xml_declaration=True))
                else:
                    zout.writestr(item, zin.read(item.filename))
        return out_path

    raise ValueError(f"Limpieza automática aún no soportada para formato '{ext}'.")


def analyze_file(path: Path) -> dict:
    fs_meta = get_linux_fs_metadata(path)
    crypto_magic = get_hashes_and_magic(path)
    alerts = []

    if crypto_magic["extension_mismatch"]:
        alerts.append(
            f"Extensión sospechosa: extensión '{path.suffix}' no coincide con Magic Bytes ({crypto_magic['detected_type']})."
        )

    internal_meta = {}
    ext = path.suffix.lower()
    try:
        if ext in {".jpg", ".jpeg", ".png", ".webp", ".tiff"} or crypto_magic["detected_type"] in {"JPEG", "PNG"}:
            internal_meta = extract_image_metadata(path)
        elif ext == ".pdf" or crypto_magic["detected_type"] == "PDF":
            internal_meta, pdf_alerts = extract_pdf_metadata(path)
            alerts.extend(pdf_alerts)
        elif ext in {".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp"}:
            internal_meta = extract_zip_xml_metadata(path)
    except Exception as e:
        alerts.append(f"Error leyendo metadatos internos: {e}")

    alerts.extend(detect_temporal_anomalies(internal_meta))

    return {
        "file": str(path),
        "internal_green": internal_meta,
        "system_yellow": fs_meta["yellow"],
        "immutable_red": {
            "Magic Bytes": f"{crypto_magic['magic_hex']} ({crypto_magic['detected_type']})",
            **fs_meta["red"],
            "MD5": crypto_magic["md5"],
            "SHA-256": crypto_magic["sha256"],
        },
        "alerts": alerts,
    }


def render_report(report: dict):
    tree = Tree(f"[bold white]ANATOMÍA DE METADATOS: {report['file']}[/bold white]")

    g_branch = tree.add("[bold green][Verde: Modificable directamente / Metadatos Internos][/bold green]")
    if report["internal_green"]:
        for k, v in report["internal_green"].items():
            g_branch.add(f"[green]{k:<24}[/green] : [white]{v}[/white]")
    else:
        g_branch.add("[dim]No se encontraron metadatos internos legibles[/dim]")

    y_branch = tree.add("[bold yellow][Amarillo: Modificable con rastro en el SO Linux][/bold yellow]")
    for k, v in report["system_yellow"].items():
        y_branch.add(f"[yellow]{k:<24}[/yellow] : [white]{v}[/white]")

    r_branch = tree.add("[bold red][Rojo: No modificable / Calculado por el Kernel o Hash][/bold red]")
    for k, v in report["immutable_red"].items():
        r_branch.add(f"[red]{k:<24}[/red] : [white]{v}[/white]")

    console.print(tree)

    if report["alerts"]:
        alert_text = "\n".join(f"• {a}" for a in report["alerts"])
        console.print(Panel(alert_text, title="[bold red]ALERTAS FORENSES[/bold red]", border_style="red"))
    console.print()


def main():
    parser = argparse.ArgumentParser(
        description="MetaInspector (Linux) - Analizador y sanitizador forense de metadatos"
    )
    parser.add_argument("target", help="Archivo o directorio a analizar")
    parser.add_argument("-r", "--recursive", action="store_true", help="Analizar carpetas de forma recursiva")
    parser.add_argument("--json", metavar="SALIDA.json", help="Exportar reporte completo a JSON")
    parser.add_argument("--strip", action="store_true", help="Generar una copia limpia sin metadatos internos")
    args = parser.parse_args()

    target = Path(args.target)
    if not target.exists():
        console.print(f"[bold red]Error:[/bold red] No existe '{target}'")
        sys.exit(1)

    if target.is_file():
        files = [target]
    else:
        iterator = target.rglob("*") if args.recursive else target.glob("*")
        files = [p for p in iterator if p.is_file()]

    results = []
    for f in files:
        rep = analyze_file(f)
        results.append(rep)
        render_report(rep)

        if args.strip:
            try:
                cleaned = strip_metadata(f)
                console.print(f"[bold cyan][✓] Copia limpia creada:[/bold cyan] {cleaned}\n")
            except Exception as e:
                console.print(f"[bold red][!] No se pudo limpiar {f.name}:[/bold red] {e}\n")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as jf:
            json.dump(results, jf, indent=2, ensure_ascii=False)
        console.print(f"[bold green]Reporte exportado a:[/bold green] {args.json}")


if __name__ == "__main__":
    main()
