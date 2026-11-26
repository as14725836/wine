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
                    resolved = Path(os.path.normpath(str(path.parent / target)))
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


def install(lock, cache):
    if (os.environ.get("GITHUB_ACTIONS") != "true" or
            os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted" or
            os.environ.get("RUNNER_ARCH") != "ARM64" or platform.system() != "Linux" or
            platform.machine().lower() not in ("aarch64", "arm64")):
        raise RuntimeError("--install requires a disposable GitHub-hosted Linux ARM64 runner")
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
    # Do not export the Termux libc through LD_LIBRARY_PATH: host Python/make
    # must continue to use Ubuntu libc. The official loader has its own prefix.
    env = os.environ.copy()
    env.pop("LD_LIBRARY_PATH", None)
    env.pop("LD_PRELOAD", None)
    report = cache / "toolchain-checks.txt"
    env["LC_ALL"] = "C"
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
