# API

## ShieldBuilder

`ShieldBuilder(master_secret: bytes)` membangun secure package dari source Python.

## ShieldLoader

`ShieldLoader(master_secret: bytes)` memverifikasi, mendekripsi, dan mengeksekusi package.

## CLI

- `pyshieldbuilder build <src> -e module:function -o dist/file.psb`
- `pyshieldbuilder run dist/file.psb`
