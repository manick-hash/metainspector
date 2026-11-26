# MetaInspector

Analizador y sanitizador forense de metadatos para Linux.

## Instalación en Linux (Kali / Debian / Ubuntu)

```bash
sudo apt update && sudo apt install -y pipx
pipx ensurepath
exec $SHELL
pipx install git+https://github.com/manick-hash/metainspector.git
```

## Uso básico

```bash
metainspector archivo.pdf
metainspector carpeta/ -r
metainspector foto.jpg --strip
metainspector archivo.docx --json reporte.json
```

## Actualizar o desinstalar

```bash
pipx upgrade metainspector
pipx uninstall metainspector
```
