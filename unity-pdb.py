"""Downloads the PDB for a UnityPlayer.dll from Unity's symbol server and places it next to the DLL.

Usage: python unity_pdb.py path\\to\\UnityPlayer.dll
"""

import os
import shutil
import struct
import subprocess
import sys
import urllib.error
import urllib.request
import uuid

SYMBOL_SERVER = "https://symbolserver.unity3d.com"


def get_pdb_info(dll_path):
    """Returns (guid_age, pdb_name) from the PE's CodeView (RSDS) debug entry."""
    with open(dll_path, "rb") as f:
        data = f.read()

    if data[:2] != b"MZ":
        sys.exit("Error: file is not a valid PE image.")
    pe, = struct.unpack_from("<I", data, 0x3C)
    if data[pe:pe + 4] != b"PE\0\0":
        sys.exit("Error: file is not a valid PE image.")

    num_sections, = struct.unpack_from("<H", data, pe + 6)
    opt_size, = struct.unpack_from("<H", data, pe + 20)
    opt = pe + 24
    magic, = struct.unpack_from("<H", data, opt)
    data_dirs = opt + (112 if magic == 0x20B else 96)
    debug_rva, debug_size = struct.unpack_from("<II", data, data_dirs + 6 * 8)  # IMAGE_DIRECTORY_ENTRY_DEBUG

    debug_off = None
    for i in range(num_sections):
        vsize, va, raw_size, raw_ptr = struct.unpack_from("<IIII", data, opt + opt_size + i * 40 + 8)
        if debug_rva and va <= debug_rva < va + max(vsize, raw_size):
            debug_off = debug_rva - va + raw_ptr
    if debug_off is None:
        sys.exit("Error: could not find the debug directory in the PE header.")

    for i in range(debug_size // 28):
        dbg_type, size_of_data, _, ptr_raw = struct.unpack_from("<IIII", data, debug_off + i * 28 + 12)
        if dbg_type != 2 or data[ptr_raw:ptr_raw + 4] != b"RSDS":  # IMAGE_DEBUG_TYPE_CODEVIEW
            continue
        guid = uuid.UUID(bytes_le=data[ptr_raw + 4:ptr_raw + 20])
        age, = struct.unpack_from("<I", data, ptr_raw + 20)
        raw_name = data[ptr_raw + 24:ptr_raw + size_of_data].split(b"\0", 1)[0].decode("utf-8", "replace")
        pdb_name = os.path.splitext(raw_name.replace("/", "\\").rsplit("\\", 1)[-1])[0]
        if pdb_name:
            return f"{guid.hex.upper()}{age:X}", pdb_name

    sys.exit("Error: could not find PDB information in the debug directory.")


def download_file(url, out_path):
    """Returns True on success, the HTTP status code on HTTP errors, or False on other failures."""
    req = urllib.request.Request(url, headers={"User-Agent": "Microsoft-Symbol-Server/10.0.0.0"})
    try:
        with urllib.request.urlopen(req) as resp, open(out_path, "wb") as out:
            total = int(resp.headers.get("Content-Length") or 0)
            done = 0
            while chunk := resp.read(81920):
                out.write(chunk)
                done += len(chunk)
                if total:
                    pct = done * 100 // total
                    print(f"\rDownloading... [{'#' * (pct // 4):<25}] {pct:3d}% "
                          f"({done / 1048576:.1f}/{total / 1048576:.1f} MiB)", end="", flush=True)
        print()
        return True
    except urllib.error.HTTPError as e:
        result = e.code
        if e.code != 404:
            print(f"Error: web request failed: {e.code} {e.reason}.")
    except Exception as e:
        print(f"\nError: download failed: {e}")
        result = False
    if os.path.exists(out_path):
        os.remove(out_path)
    return result


def extract_cab(cab_path, out_dir):
    print("Unpacking PDB...")
    if os.name == "nt":
        # expand.exe names single-file CAB output after the archive itself, so pass the embedded name explicitly.
        listing = subprocess.run(["expand.exe", "-D", cab_path], capture_output=True, text=True).stdout
        cab_name = os.path.basename(cab_path).lower()
        names = [line.rsplit(": ", 1)[1].strip() for line in listing.splitlines()
                 if ": " in line and line.rsplit(": ", 1)[0].lower().endswith(cab_name)]
        if len(names) == 1:
            cmd = ["expand.exe", cab_path, os.path.join(out_dir, names[0])]
        else:
            cmd = ["expand.exe", cab_path, "-F:*", out_dir]
    elif shutil.which("cabextract"):
        cmd = ["cabextract", "-q", "-d", out_dir, cab_path]
    else:
        print("Error: 'cabextract' is required to unpack the archive on this platform.")
        return False

    result = subprocess.run(cmd, capture_output=True, text=True)
    os.remove(cab_path)
    if result.returncode != 0:
        print(f"Error: extraction failed:\n{result.stdout}{result.stderr}")
        return False
    return True


def main():
    if len(sys.argv) != 2:
        sys.exit(f"Usage: {os.path.basename(sys.argv[0])} path\\to\\UnityPlayer.dll")

    dll_path = os.path.abspath(sys.argv[1].strip('"'))
    if not os.path.isfile(dll_path):
        sys.exit(f"Error: file not found: {dll_path}")

    guid, pdb_name = get_pdb_info(dll_path)
    out_dir = os.path.dirname(dll_path)
    cab_path = os.path.join(out_dir, f"{pdb_name}.cab")
    pdb_path = os.path.join(out_dir, f"{pdb_name}.pdb")
    base_url = f"{SYMBOL_SERVER}/{pdb_name}.pdb/{guid}"

    # Older Unity versions publish a CAB-compressed .pd_; Unity 6+ publishes the raw .pdb.
    status = None
    for file_name, out_path in ((f"{pdb_name}.pd_", cab_path), (f"{pdb_name}.pdb", pdb_path)):
        print(f"Trying {base_url}/{file_name}")
        status = download_file(f"{base_url}/{file_name}", out_path)
        if status != 404:
            break
    if status is not True:
        sys.exit("Error: PDB not found on Unity's symbol server." if status == 404 else 1)

    with open(out_path, "rb") as f:
        is_cab = f.read(4) == b"MSCF"
    if is_cab:
        if not extract_cab(out_path, out_dir):
            return 1
    elif out_path != pdb_path:
        os.replace(out_path, pdb_path)

    print(f"Done: {pdb_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
