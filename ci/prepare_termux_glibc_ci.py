#!/usr/bin/env python3
"""Prepare a pinned Termux glibc prefix on a disposable GitHub ARM64 runner.

--check-only validates the lock using host dpkg; no downloads or compilers.
--install is deliberately restricted to GitHub-hosted Linux ARM64 runners.
Package maintainer scripts are never executed. This is not a Termux installer.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import urllib.request

BASE_URL = "https://packages.termux.dev/apt/termux-glibc/"
PREFIX = Path("/data/data/com.termux/files/usr/glibc")
CLASSICAL_PREFIX = PREFIX.parent
# LLVM 19 in the official lock still needs the pre-2.14 libxml2 SONAME.
# Pin the source/hash from Termux's historical libxml2 2.13.6 recipe:
# https://github.com/termux-pacman/glibc-packages/blob/16a5e6853837f8c67248bc72c6893aba8d2acb99/gpkg/libxml2/build.sh
XML_VERSION = "2.13.6"
XML_URL = f"https://download.gnome.org/sources/libxml2/2.13/libxml2-{XML_VERSION}.tar.xz"
XML_SHA256 = "f453480307524968f7a04ec65e64f2a83a825973bcd260a2e7691be82ae70c96"


def dependencies(text):
    for group in text.split(","):
        if not group.strip():
            continue
        choices = []
        for alternative in group.split("|"):
            match = re.fullmatch(r"\s*([a-z0-9+.-]+)(?:\s*\((=|>=|<=|>>|<<)\s*([^()]+)\))?\s*", alternative)
            if not match:
                raise ValueError(f"Unsupported dependency: {alternative}")
            choices.append(match.groups())
        yield choices


def load_lock(path):
    lock = json.loads(path.read_text())
    if lock["schema"] != 1 or lock["base_url"] != BASE_URL or lock["prefix"] != str(PREFIX):
        raise ValueError("Unexpected lock schema, repository or prefix")
    records = {}
    for record in lock["packages"]:
        name = record["name"]
        if not re.fullmatch(r"[a-z0-9+.-]+", name) or name in records:
            raise ValueError(f"Invalid or duplicate package: {name}")
        filename = PurePosixPath(record["filename"])
        if (filename.is_absolute() or ".." in filename.parts or
                not str(filename).startswith("pool/stable/") or filename.suffix != ".deb"):
            raise ValueError(f"Invalid package filename: {filename}")
        if record["architecture"] not in ("aarch64", "all"):
            raise ValueError(f"Wrong package architecture: {name}")
        if not re.fullmatch(r"[0-9a-f]{64}", record["sha256"]) or record["size"] <= 0:
            raise ValueError(f"Invalid checksum or size: {name}")
        records[name] = record
    # resolv-conf is a configuration-only package from Termux main. In CI its
    # configuration is supplied explicitly from the runner, with no Bionic ELF.
    if lock["host_configuration_dependencies"] != ["resolv-conf"]:
        raise ValueError("Unexpected external dependency exception")
    for root in lock["roots"]:
        if root not in records:
            raise ValueError(f"Missing root package: {root}")
    for record in records.values():
        for choices in dependencies(record["depends"]):
            if not any(name in records or name == "resolv-conf" for name, _, _ in choices):
                raise ValueError(f"Unresolved dependency of {record['name']}: {choices}")
            satisfied = False
            for name, operator, version in choices:
                if name == "resolv-conf" and not operator:
                    satisfied = True
                elif name in records:
                    if not operator:
                        satisfied = True
                    else:
                        comparison = {"=": "eq", ">=": "ge", "<=": "le", ">>": "gt", "<<": "lt"}[operator]
                        result = subprocess.run(["dpkg", "--compare-versions", records[name]["version"], comparison, version])
                        if result.returncode not in (0, 1):
                            raise ValueError(f"Invalid version constraint: {choices}")
                        satisfied |= result.returncode == 0
            if not satisfied:
                raise ValueError(f"Unsatisfied version constraint: {choices}")
    return lock


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def run(*args, **kwargs):
    print("+", " ".join(map(str, args)), flush=True)
    return subprocess.run(list(map(str, args)), check=True, **kwargs)


def validate_payload(archive):
    # Inspect the data archive using the host dpkg-deb. Parent directories are
    # allowed; all non-directory payloads must remain under the Termux prefix.
    proc = subprocess.Popen(["dpkg-deb", "--fsys-tarfile", str(archive)], stdout=subprocess.PIPE)
    try:
        with tarfile.open(fileobj=proc.stdout, mode="r|") as stream:
            for member in stream:
                path = PurePosixPath("/") / PurePosixPath(member.name)
                if ".." in path.parts or (path != CLASSICAL_PREFIX and
                        CLASSICAL_PREFIX not in path.parents and
                        not (member.isdir() and path in CLASSICAL_PREFIX.parents)):
                    raise ValueError(f"Unexpected package payload: {member.name}")
                if not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
                    raise ValueError(f"Unsupported package entry: {member.name}")
                if member.issym() or member.islnk():
                    target = member.linkname
                    # Linux treats // as /, but normpath preserves exactly two
                    # leading slashes. Canonicalize the root before containment
                    # checks (the official GCC package uses //data/... links).
                    resolved = Path(os.path.normpath("/" + str(path.parent / target).lstrip("/")))
                    if member.islnk():
                        resolved = Path(os.path.normpath("/" + target.lstrip("/")))
                    if resolved != CLASSICAL_PREFIX and CLASSICAL_PREFIX not in resolved.parents:
                        raise ValueError(f"Package link escapes prefix: {member.name} -> {target}")
        if proc.wait() != 0:
            raise RuntimeError(f"Cannot inspect {archive}")
    finally:
        proc.stdout.close()
        if proc.poll() is None:
            proc.terminate()
        proc.wait()


def require_runner():
    if (os.environ.get("GITHUB_ACTIONS") != "true" or
            os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted" or
            os.environ.get("RUNNER_ARCH") != "ARM64" or platform.system() != "Linux" or
            platform.machine().lower() not in ("aarch64", "arm64")):
        raise RuntimeError("--install requires a disposable GitHub-hosted Linux ARM64 runner")


def build_xml_compat(cache):
    """Bootstrap LLVM's real legacy XML ABI using only the runner's host GCC."""
    require_runner()
    archive = cache / f"libxml2-{XML_VERSION}.tar.xz"
    if not archive.exists():
        partial = archive.with_suffix(".partial")
        with urllib.request.urlopen(XML_URL, timeout=120) as response, partial.open("wb") as out:
            shutil.copyfileobj(response, out)
        if sha256(partial) != XML_SHA256:
            raise RuntimeError("libxml2 compatibility source checksum mismatch")
        partial.replace(archive)
    if sha256(archive) != XML_SHA256:
        raise RuntimeError("Cached libxml2 compatibility source checksum mismatch")
    build = cache / "libxml2-compat-build"
    build.mkdir(exist_ok=False)
    with tarfile.open(archive) as stream:
        members = stream.getmembers()
        for member in members:
            path = PurePosixPath(member.name)
            if (path.is_absolute() or ".." in path.parts or not path.parts or
                    path.parts[0] != f"libxml2-{XML_VERSION}" or
                    not (member.isfile() or member.isdir())):
                raise ValueError(f"Unsafe XML source archive entry: {member.name}")
        stream.extractall(build, members=members)
    source = build / f"libxml2-{XML_VERSION}"
    env = os.environ.copy()
    for name in ("LD_LIBRARY_PATH", "LD_PRELOAD", "LIBRARY_PATH", "CPATH",
                 "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "COMPILER_PATH",
                 "GCC_EXEC_PREFIX", "CPPFLAGS", "CFLAGS", "CXXFLAGS", "LDFLAGS",
                 "CC", "CXX", "CPP", "LD", "AR", "RANLIB", "NM", "STRIP",
                 "CONFIG_SITE", "PKG_CONFIG_PATH", "PKG_CONFIG_LIBDIR", "PKG_CONFIG_SYSROOT_DIR"):
        env.pop(name, None)
    env.update(PATH="/usr/bin:/bin", LC_ALL="C", CC="/usr/bin/gcc", CFLAGS="-O2",
               PKG_CONFIG="/usr/bin/false", CONFIG_SITE="/dev/null")
    report = cache / "libxml2-compat-build.log"
    with report.open("w") as out:
        options = dict(cwd=source, env=env, stdout=out, stderr=subprocess.STDOUT)
        run("/bin/sh", "./configure", "--disable-static", "--without-python",
            "--without-zlib", "--without-lzma", "--without-iconv", "--without-icu",
            "--without-readline", "--without-modules", **options)
        # Do not install headers, pkg-config files, utilities or the .so linker
        # name: the locked current libxml2 package must remain intact.
        run("/usr/bin/make", "-j2", "libxml2.la", **options)
        library = (source / ".libs/libxml2.so.2").resolve(strict=True)
        if library.parent != source / ".libs" or not library.name.startswith("libxml2.so.2."):
            raise RuntimeError("Unexpected compatibility library output")
        headers = subprocess.check_output(["readelf", "-h", str(library)], text=True, env=env)
        dynamic = subprocess.check_output(["readelf", "-d", str(library)], text=True, env=env)
        versions = subprocess.check_output(["readelf", "--version-info", str(library)], text=True, env=env)
        out.write(headers + dynamic + versions)
        if "AArch64" not in headers or not re.search(r"\(SONAME\).*\[libxml2\.so\.2\]", dynamic):
            raise RuntimeError("Wrong architecture or SONAME for XML compatibility library")
        needed = re.findall(r"\(NEEDED\).*\[(.*?)\]", dynamic)
        if not needed or set(needed) - {"libc.so.6", "libm.so.6"}:
            raise RuntimeError(f"Unexpected XML compatibility dependencies: {needed}")
        if any(version not in versions for version in ("LIBXML2_2.4.30", "LIBXML2_2.6.0")):
            raise RuntimeError("XML compatibility library lacks LLVM's symbol versions")
        for name in (library.name, "libxml2.so.2"):
            if (PREFIX / "lib" / name).exists() or (PREFIX / "lib" / name).is_symlink():
                raise RuntimeError(f"Refusing to overwrite existing XML library: {name}")
        run("sudo", "install", "-m", "755", library, PREFIX / "lib" / library.name)
        run("sudo", "ln", "-s", library.name, PREFIX / "lib/libxml2.so.2")
    (cache / "libxml2-compat.json").write_text(json.dumps({
        "version": XML_VERSION, "source_url": XML_URL, "source_sha256": XML_SHA256,
        "library": library.name, "library_sha256": sha256(library),
        "compiler": "/usr/bin/gcc (GitHub runner only)", "needed": needed,
    }, indent=2) + "\n")
    print(f"Built legacy XML ABI for the Termux compiler; log: {report}", flush=True)


def install(lock, cache):
    require_runner()
    if CLASSICAL_PREFIX.exists():
        raise RuntimeError(f"Refusing to overwrite existing prefix: {CLASSICAL_PREFIX}")
    cache.mkdir(parents=True, exist_ok=True)
    root = cache / "root"
    root.mkdir(exist_ok=False)
    for record in lock["packages"]:
        archive = cache / PurePosixPath(record["filename"]).name
        if not archive.exists():
            partial = archive.with_suffix(".partial")
            print(f"Downloading {record['name']} {record['version']}", flush=True)
            with urllib.request.urlopen(BASE_URL + record["filename"], timeout=120) as response, partial.open("wb") as out:
                shutil.copyfileobj(response, out)
            if partial.stat().st_size != record["size"] or sha256(partial) != record["sha256"]:
                raise RuntimeError(f"Downloaded package checksum mismatch: {record['name']}")
            partial.replace(archive)
        if archive.stat().st_size != record["size"] or sha256(archive) != record["sha256"]:
            raise RuntimeError(f"Cached package checksum mismatch: {record['name']}")
        metadata = subprocess.check_output(
            ["dpkg-deb", "--show", "--showformat=${Package}\n${Version}\n${Architecture}\n", str(archive)],
            text=True).splitlines()
        if metadata != [record["name"], record["version"], record["architecture"]]:
            raise RuntimeError(f"Package metadata mismatch: {archive}")
        validate_payload(archive)
        run("dpkg-deb", "--extract", archive, root)
    run("sudo", "install", "-d", "-m", "755", CLASSICAL_PREFIX)
    run("sudo", "cp", "-a", str(root / CLASSICAL_PREFIX.relative_to("/")) + "/.", CLASSICAL_PREFIX)
    run("sudo", "install", "-d", "-m", "1777", CLASSICAL_PREFIX / "tmp")
    run("sudo", "install", "-d", "-m", "755", CLASSICAL_PREFIX / "etc")
    run("sudo", "cp", "-L", "/etc/resolv.conf", CLASSICAL_PREFIX / "etc/resolv.conf")
    for name in ("bin/clang", "bin/clang++", "bin/ld.lld", "lib/ld-linux-aarch64.so.1", "lib/libc.so.6"):
        if not (PREFIX / name).is_file():
            raise RuntimeError(f"Required extracted file missing: {name}")
    build_xml_compat(cache)
    # Do not export the Termux libc through LD_LIBRARY_PATH: host Python/make
    # must continue to use Ubuntu libc. The official loader has its own prefix.
    env = os.environ.copy()
    env.pop("LD_LIBRARY_PATH", None)
    env.pop("LD_PRELOAD", None)
    report = cache / "toolchain-checks.txt"
    env["LC_ALL"] = "C"
    env["LD_BIND_NOW"] = "1"
    with report.open("w") as out:
        for executable in (PREFIX / "bin/clang", PREFIX / "bin/ld.lld"):
            headers = subprocess.check_output(["readelf", "-l", str(executable)], text=True, env=env)
            out.write(headers)
            out.flush()
            interpreter = re.search(r"\[Requesting program interpreter: (.*?)\]", headers)
            expected_loader = str(PREFIX / "lib/ld-linux-aarch64.so.1")
            if not interpreter or interpreter.group(1) != expected_loader:
                raise RuntimeError(f"Unexpected toolchain ELF interpreter: {executable}")
            run("readelf", "-d", executable, stdout=out, stderr=subprocess.STDOUT)
            result = subprocess.run([expected_loader, "--list", str(executable)], env=env,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            out.write(result.stdout)
            out.flush()
            result.check_returncode()
            for library in re.findall(r"(/[^\s()]+)", result.stdout):
                resolved = Path(library).resolve()
                if PREFIX not in resolved.parents:
                    raise RuntimeError(f"Toolchain resolved a library outside glibc prefix: {library}")
            run(executable, "--version", env=env, stdout=out, stderr=subprocess.STDOUT)
    print(f"Prepared {len(lock['packages'])} pinned packages; loader checks: {report}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, default=Path(__file__).with_name("termux-glibc-aarch64.lock.json"))
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check-only", action="store_true")
    mode.add_argument("--install", action="store_true")
    parser.add_argument("--cache-dir", type=Path)
    args = parser.parse_args()
    lock = load_lock(args.lock)
    if args.check_only:
        print(f"Lock valid: {len(lock['packages'])} packages; {sum(p['size'] for p in lock['packages'])} download bytes")
        return 0
    if not args.cache_dir:
        parser.error("--install requires --cache-dir")
    install(lock, args.cache_dir.resolve())
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
