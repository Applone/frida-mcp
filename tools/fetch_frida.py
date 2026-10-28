#!/usr/bin/env python3
"""Fetch pinned official Frida assets and verify the release API's SHA-256 digest.

Only the requested devkit files are extracted. No sudo or system installation.
Gadget installation is an explicit operation, separate from health diagnostics.
"""

import argparse
import hashlib
import json
import lzma
import os
from pathlib import Path
import platform
import shutil
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
VERSION = (ROOT / ".frida-version").read_text().strip()


def sha256(path):
    with open(path, "rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def fetch(url, output, maximum=1024 * 1024 * 1024):
    request = urllib.request.Request(url, headers={"User-Agent": "frida-mcp-build/0.1"})
    with urllib.request.urlopen(request, timeout=120) as response, open(output, "wb") as handle:
        count = 0
        while chunk := response.read(1024 * 1024):
            count += len(chunk)
            if count > maximum:
                raise RuntimeError("Frida asset exceeded download limit")
            handle.write(chunk)


def download_asset(name, destination):
    api = f"https://api.github.com/repos/frida/frida/releases/tags/{VERSION}"
    request = urllib.request.Request(api, headers={"User-Agent": "frida-mcp-build/0.1"})
    with urllib.request.urlopen(request, timeout=30) as response:
        release = json.loads(response.read(8 * 1024 * 1024))
    matches = [asset for asset in release["assets"] if asset["name"] == name]
    if len(matches) != 1:
        raise RuntimeError(f"Official release {VERSION} has no unique asset {name}")
    asset = matches[0]
    digest = asset.get("digest") or ""
    if not digest.startswith("sha256:") or len(digest) != 71:
        raise RuntimeError("Release API has no SHA-256 digest; refusing an unverified download")
    url = asset["browser_download_url"]
    expected = f"https://github.com/frida/frida/releases/download/{VERSION}/"
    if not url.startswith(expected):
        raise RuntimeError("Unexpected Frida asset URL")
    fetch(url, destination)
    if sha256(destination) != digest[7:]:
        raise RuntimeError("Frida asset SHA-256 mismatch")
    return digest


def extract_devkit(archive, destination):
    wanted = {"frida-core.h", "libfrida-core.a"}
    found = set()
    with tarfile.open(archive, "r:xz") as tar:
        for member in tar:
            name = Path(member.name).name
            if name not in wanted:
                continue
            if not member.isfile() or name in found or member.size > 1024 * 1024 * 1024:
                raise RuntimeError(f"Unsafe or duplicate devkit entry: {member.name}")
            found.add(name)
            with tar.extractfile(member) as source, open(destination / name, "wb") as output:
                shutil.copyfileobj(source, output)
    if found != wanted:
        raise RuntimeError(f"Missing devkit files: {wanted - found}")


def cached(destination):
    try:
        manifest = json.loads((destination / "verified.json").read_text())
        return manifest["version"] == VERSION and all(
            sha256(destination / name) == digest for name, digest in manifest["files"].items()
        ) and set(manifest["files"]) == {"frida-core.h", "libfrida-core.a"}
    except (OSError, ValueError, KeyError):
        return False


def devkit():
    if platform.system() != "Linux":
        raise RuntimeError("The initial native backend supports Linux")
    machine = platform.machine()
    architectures = {"x86_64": "x86_64", "amd64": "x86_64", "aarch64": "arm64", "arm64": "arm64"}
    if machine not in architectures:
        raise RuntimeError(f"Unsupported host architecture: {machine}")
    arch = architectures[machine]
    destination = ROOT / ".deps" / f"frida-{VERSION}-linux-{arch}"
    if cached(destination):
        print(destination)
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=destination.parent) as work:
        work = Path(work)
        archive = work / "devkit.tar.xz"
        digest = download_asset(f"frida-core-devkit-{VERSION}-linux-{arch}.tar.xz", archive)
        extract_devkit(archive, work)
        manifest = {"version": VERSION, "asset_digest": digest,
                    "files": {name: sha256(work / name) for name in ("frida-core.h", "libfrida-core.a")}}
        destination.mkdir(exist_ok=True)
        for name in manifest["files"]:
            os.replace(work / name, destination / name)
        (work / "verified.json").write_text(json.dumps(manifest, indent=2) + "\n")
        os.replace(work / "verified.json", destination / "verified.json")
    print(destination)


def gadget(cache_dir):
    destination = cache_dir / "frida" / "gadget-ios.dylib"
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=destination.parent) as work:
        work = Path(work)
        archive = work / "gadget.xz"
        digest = download_asset(f"frida-gadget-{VERSION}-ios-universal.dylib.xz", archive)
        unpacked = work / "gadget-ios.dylib"
        with lzma.open(archive) as source, open(unpacked, "wb") as output:
            shutil.copyfileobj(source, output)
        unpacked.chmod(0o644)
        os.replace(unpacked, destination)
        destination.with_suffix(".dylib.version").write_text(VERSION + "\n" + digest + "\n")
    print(destination)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("asset", choices=("devkit", "gadget"))
    parser.add_argument("--cache-dir", type=Path,
                        default=Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")))
    args = parser.parse_args()
    if args.asset == "devkit":
        devkit()
    else:
        gadget(args.cache_dir)


if __name__ == "__main__":
    main()
