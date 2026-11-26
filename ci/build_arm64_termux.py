#!/usr/bin/env python3
"""Build and supervise native ARM64 Wine for Termux glibc (Python 3.9+)."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import selectors
import shlex
import shutil
import signal
import struct
import subprocess
import sys
import tarfile
import time

URL = "https://github.com/as14725836/wine.git"
BRANCH = "upgrade/dwproton-11.0-17"
ENV_KEYS = ("CC", "CXX", "CFLAGS", "CXXFLAGS", "CPPFLAGS", "LDFLAGS", "CROSSCFLAGS",
            "CROSSLDFLAGS", "PATH", "LD_LIBRARY_PATH", "LIBRARY_PATH", "CPATH",
            "PKG_CONFIG_PATH", "PKG_CONFIG_LIBDIR", "PKG_CONFIG_SYSROOT_DIR",
            "BISON_PKGDATADIR", "M4", "AUTOCONF", "AUTOHEADER", "AUTOM4TE",
            "AUTOM4TE_CFG", "ACLOCAL_PATH", "AC_MACRODIR", "autom4te_perllibdir", "trailer_m4",
            "aarch64_CC")


def atomic_json(path, data):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
    temporary.replace(path)


def elf_info(path):
    data = Path(path).read_bytes()
    if data[:6] != b"\x7fELF\x02\x01":
        raise RuntimeError(f"Expected ELF64 little-endian: {path}")
    machine = struct.unpack_from("<H", data, 18)[0]
    if machine != 183:
        raise RuntimeError(f"Expected AArch64 ELF, got machine {machine}: {path}")
    phoff = struct.unpack_from("<Q", data, 32)[0]
    entsize, count = struct.unpack_from("<HH", data, 54)
    interpreter = None
    for i in range(count):
        off = phoff + i * entsize
        if struct.unpack_from("<I", data, off)[0] == 3:
            start = struct.unpack_from("<Q", data, off + 8)[0]
            size = struct.unpack_from("<Q", data, off + 32)[0]
            interpreter = data[start:start + size].rstrip(b"\0").decode()
    return {"machine": "AArch64", "interpreter": interpreter}


def verify_pe(path):
    data = Path(path).read_bytes()
    if data[:2] != b"MZ":
        raise RuntimeError(f"Expected PE executable: {path}")
    off = struct.unpack_from("<I", data, 60)[0]
    if data[off:off + 4] != b"PE\0\0" or struct.unpack_from("<H", data, off + 4)[0] != 0xaa64:
        raise RuntimeError(f"Expected ARM64 PE (0xaa64): {path}")
    return {"machine": "ARM64", "machine_id": "0xaa64"}


class Supervisor:
    def __init__(self, args):
        self.args = args
        self.work = args.work_dir.expanduser().resolve()
        self.work.mkdir(parents=True, exist_ok=True)
        self.stop = False
        self.state = {"pid": os.getpid(), "started": time.time(), "profile": args.profile}
        self.env = os.environ.copy()
        gp = args.glibc_prefix.expanduser().resolve()
        self.env.setdefault("CC", str(gp / "bin/clang") if args.profile == "termux" else "clang")
        self.env.setdefault("CXX", str(gp / "bin/clang++") if args.profile == "termux" else "clang++")
        self.env.setdefault("CFLAGS", "-O2")
        self.env.setdefault("CXXFLAGS", "-O2")
        if args.profile == "termux":
            compiler = gp / "bin/clang"
            self.env["PATH"] = f"{gp}/bin:" + self.env.get("PATH", "")
            self.env.setdefault("aarch64_CC", str(compiler))
            # Keep pkg-config from silently discovering bionic libraries.
            self.env["PKG_CONFIG_LIBDIR"] = f"{gp}/lib/pkgconfig:{gp}/share/pkgconfig"
            self.env["PKG_CONFIG_PATH"] = ""
            self.env["PKG_CONFIG_SYSROOT_DIR"] = ""
            ldflags = shlex.split(self.env.get("LDFLAGS", ""))
            ldflags += [f"-Wl,--dynamic-linker={gp}/lib/ld-linux-aarch64.so.1",
                        f"-Wl,-rpath,{gp}/lib"]
            self.env["LDFLAGS"] = shlex.join(ldflags)
        self._relocate_autoconf_config()
        self.log = None
        self.phase = "starting"
        self.last_output = time.time()
        signal.signal(signal.SIGINT, self.interrupt)
        signal.signal(signal.SIGTERM, self.interrupt)

    def _relocate_autoconf_config(self):
        macrodir = self.env.get("AC_MACRODIR") or self.env.get("autom4te_perllibdir")
        if not macrodir:
            return
        config = Path(self.env.get("AUTOM4TE_CFG", str(Path(macrodir) / "autom4te.cfg")))
        if not config.is_file():
            return
        text = config.read_text()
        if "/usr/share/autoconf" not in text or macrodir == "/usr/share/autoconf":
            return
        relocated = self.work / "tool-config" / "autom4te.cfg"
        relocated.parent.mkdir(parents=True, exist_ok=True)
        # Use macro sources to keep the relocated tool configuration self-contained.
        text = text.replace("/usr/share/autoconf", macrodir).replace(".m4f", ".m4")
        relocated.write_text(text)
        self.env["AUTOM4TE_CFG"] = str(relocated)

    def interrupt(self, *_):
        self.stop = True

    def status(self, state, **extra):
        self.state.update(state=state, phase=self.phase, updated=time.time(),
                          last_output=self.last_output, **extra)
        atomic_json(self.work / "status.json", self.state)

    def note(self, text):
        line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {text}\n"
        sys.stdout.write(line)
        sys.stdout.flush()
        if self.log:
            self.log.write(line.encode())
            self.log.flush()

    def cancelled(self):
        return self.stop or (self.work / "STOP").exists()

    def run(self, argv, cwd=None, phase=None, timeout=None, env=None):
        if self.cancelled():
            raise InterruptedError("Stopped; remove the STOP file before resuming")
        if phase:
            self.phase = phase
        self.note(f"{self.phase}: {shlex.join(map(str, argv))}")
        proc = subprocess.Popen(list(map(str, argv)), cwd=cwd, env=env or self.env,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                start_new_session=True)
        self.last_output = started = heartbeat = time.time()
        selector = selectors.DefaultSelector()
        selector.register(proc.stdout, selectors.EVENT_READ)
        captured = bytearray()
        reason = None
        try:
            while selector.get_map() or proc.poll() is None:
                now = time.time()
                if self.cancelled():
                    reason = "stop requested"
                    break
                if timeout and now - started > timeout:
                    reason = f"timeout after {timeout}s"
                    break
                if self.args.idle_timeout and now - self.last_output > self.args.idle_timeout:
                    reason = f"no command output for {self.args.idle_timeout}s"
                    break
                if now - heartbeat >= self.args.heartbeat:
                    self.status("running", child_pid=proc.pid, elapsed=int(now - started))
                    self.note(f"heartbeat: {self.phase}, elapsed={int(now-started)}s, "
                              f"output_idle={int(now-self.last_output)}s")
                    heartbeat = now
                for key, _ in selector.select(timeout=0.5):
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    self.last_output = time.time()
                    # Only keep the last 1 MiB in RAM; full output stays in the log.
                    captured.extend(chunk)
                    if len(captured) > 1048576:
                        del captured[:-1048576]
                    sys.stdout.buffer.write(chunk)
                    sys.stdout.buffer.flush()
                    if self.log:
                        self.log.write(chunk)
                        self.log.flush()
            if reason:
                raise InterruptedError(reason) if self.cancelled() else RuntimeError(reason)
            rc = proc.wait()
            if rc:
                raise RuntimeError(f"{self.phase}: command exited {rc}; see {self.log.name}")
            return captured.decode(errors="replace").strip()
        finally:
            # Kill the process group even when its leader exited before a child.
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                proc.poll()  # Reap the leader so its zombie cannot hold the group open.
                try:
                    os.killpg(proc.pid, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.05)
            else:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            proc.wait()
            selector.close()
            proc.stdout.close()

    def doctor(self):
        if platform.machine().lower() not in ("aarch64", "arm64"):
            raise RuntimeError("This script requires a native aarch64 host")
        if self.args.profile == "termux":
            gp = self.args.glibc_prefix.expanduser().resolve()
            expected_cc = (gp / "bin/clang").resolve()
            cc_command = os.path.expanduser(shlex.split(self.env["CC"])[0])
            actual_cc = Path(shutil.which(cc_command, path=self.env["PATH"]) or cc_command).resolve()
            if actual_cc != expected_cc:
                raise RuntimeError(f"Termux profile requires CC={expected_cc}; refusing a Bionic compiler")
            for tool in (expected_cc, gp / "bin/clang++", gp / "lib/ld-linux-aarch64.so.1"):
                if not tool.is_file():
                    raise RuntimeError(f"Missing Termux glibc tool/runtime file: {tool}; install glibc-repo, glibc-runner, clang-glibc")
        for tool in ("git", "make", "perl", "python3", "autoconf", "autoreconf", "bison",
                     "flex", "pkg-config", "readelf", "clang", "ld.lld"):
            if not shutil.which(tool, path=self.env["PATH"]):
                raise RuntimeError(f"Missing tool: {tool}; see documentation/termux-arm64-build.md")
        probe = self.work / "probe"
        probe.mkdir(exist_ok=True)
        c = probe / "glibc.c"
        c.write_text('#include <gnu/libc-version.h>\n#include <stdio.h>\n'
                     'int main(void) { puts(gnu_get_libc_version()); return 0; }\n')
        cmd = shlex.split(self.env["CC"])
        cmd += shlex.split(self.env["CPPFLAGS"] if "CPPFLAGS" in self.env else "")
        cmd += shlex.split(self.env["CFLAGS"])
        cmd += [str(c), "-o", str(probe / "glibc")]
        cmd += shlex.split(self.env.get("LDFLAGS", ""))
        self.run(cmd, phase="probe-glibc")
        info = elf_info(probe / "glibc")
        interpreter = info["interpreter"] or ""
        if not interpreter or "linker64" in interpreter or not Path(interpreter).is_file():
            raise RuntimeError(f"Invalid/missing glibc interpreter: {interpreter}")
        if self.args.profile == "termux":
            expected = str(self.args.glibc_prefix.expanduser().resolve() / "lib/ld-linux-aarch64.so.1")
            if interpreter != expected:
                raise RuntimeError(f"Expected Termux glibc interpreter {expected}, got {interpreter}")
        version = self.run([probe / "glibc"], phase="probe-glibc-runtime", timeout=30)
        pe = probe / "pe.c"
        pe.write_text("void mainCRTStartup(void) {}\n")
        pe_cmd = shlex.split(self.env.get("aarch64_CC", "clang"))
        self.run(pe_cmd + ["--no-default-config", "-target", "aarch64-windows", "-fuse-ld=lld",
                          "-nostdlib", str(pe), "-Wl,-entry:mainCRTStartup", "-Wl,-subsystem:console",
                          "-o", str(probe / "pe.exe")], phase="probe-pe", timeout=60)
        pe_info = verify_pe(probe / "pe.exe")
        compiler = self.run(shlex.split(self.env["CC"]) + ["--version"], phase="compiler-version")
        result = {"elf": info, "glibc_version": version, "pe": pe_info, "compiler": compiler}
        atomic_json(self.work / "doctor.json", result)
        return result

    def source(self):
        source = (self.args.source or self.work / "source").expanduser().resolve()
        if source == self.work or source in self.work.parents:
            raise RuntimeError("--work-dir must be outside the source tree")
        if not source.exists():
            if self.args.source:
                raise RuntimeError(f"Explicit source directory does not exist: {source}")
            self.run(["git", "clone", "--single-branch", "--branch", self.args.branch,
                      self.args.repository, source], phase="clone")
        if not (source / "configure.ac").is_file():
            raise RuntimeError(f"Not a Wine source tree: {source}")
        self.source_lock = (source / ".arm64-supervisor.lock").open("a")
        try:
            fcntl.flock(self.source_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("Another supervisor is using this source tree") from None
        sha = self.run(["git", "rev-parse", "HEAD"], source, "source-revision")
        if self.args.commit and sha != self.args.commit:
            raise RuntimeError(f"Source HEAD {sha} does not match --commit {self.args.commit}")
        # Never checkout/pull/reset an existing tree, including on supervisor retries.
        return source, sha

    def source_fingerprint(self, source):
        # Write the complete diff to disk: run() retains only a bounded log tail.
        patch = self.work / "source-changes.patch"
        self.run(["git", "diff", "--binary", "HEAD", f"--output={patch}"], source, "source-changes")
        digest = hashlib.sha256()
        with patch.open("rb") as stream:
            for block in iter(lambda: stream.read(1048576), b""):
                digest.update(block)
        untracked = subprocess.check_output(
            ["git", "-c", "core.fsmonitor=false", "ls-files", "--others", "--exclude-standard", "-z"],
            cwd=source, env=self.env, timeout=30).split(b"\0")
        # configure is ignored by git but determines the actual configuration.
        inputs = {os.fsdecode(name) for name in untracked
                  if name and "__pycache__" not in Path(os.fsdecode(name)).parts}
        inputs.add("configure")
        inputs.discard(".arm64-supervisor.lock")
        for name in sorted(inputs):
            if self.cancelled():
                raise InterruptedError("Stopped during source fingerprinting")
            path = source / name
            digest.update(os.fsencode(name) + b"\0")
            digest.update(str(path.lstat().st_mode).encode() + b"\0")
            if path.is_symlink():
                digest.update(os.fsencode(os.readlink(path)))
            else:
                with path.open("rb") as stream:
                    for block in iter(lambda: stream.read(1048576), b""):
                        digest.update(block)
            digest.update(b"\0")
        return digest.hexdigest()

    def build(self):
        doctor = self.doctor()
        source, sha = self.source()
        prefix = self.args.prefix
        if not prefix.is_absolute() or ".." in prefix.parts or prefix == Path("/"):
            raise RuntimeError("--prefix must be an absolute non-root path without '..'")
        configure = [str(source / "configure"), "--enable-option-checking=fatal",
                     f"--prefix={prefix}", f"--exec-prefix={prefix}", "--enable-archs=aarch64", "--disable-tests",
                     "--disable-win16", "--without-oss"] + self.args.configure_arg
        for arg in self.args.configure_arg:
            if arg.startswith(("--prefix", "--exec-prefix", "--bindir", "--libdir", "--enable-archs",
                               "--host", "--build", "--without-mingw", "--disable-win64")):
                raise RuntimeError(f"Option conflicts with native ARM64 layout: {arg}")
        if not (source / "configure").is_file():
            self.run(["sh", "./autogen.sh"], source, "autogen")
        config = {"source": str(source), "commit": sha, "configure": configure,
                  "source_digest": self.source_fingerprint(source),
                  "profile": self.args.profile, "doctor": doctor,
                  "environment": {k: self.env[k] for k in ENV_KEYS if k in self.env}}
        fingerprint = self.work / "build-config.json"
        if fingerprint.exists():
            if json.loads(fingerprint.read_text()) != config:
                raise RuntimeError("Source/toolchain/configuration changed. Use a NEW --work-dir; "
                                   "the existing build is preserved.")
        else:
            atomic_json(fingerprint, config)
        build = self.work / "build"
        build.mkdir(exist_ok=True)
        self.state.update(commit=sha, build_dir=str(build))
        if not (build / "Makefile").is_file() or not (self.work / "configured.json").is_file():
            self.run(configure, build, "configure")
            atomic_json(self.work / "configured.json", {"commit": sha})
        makefile = (build / "Makefile").read_text()
        archs = next((line.split("=", 1)[1].strip() for line in makefile.splitlines()
                      if line.startswith("PE_ARCHS =")), "")
        if archs != "aarch64":
            raise RuntimeError(f"Unexpected PE_ARCHS={archs!r}, expected only aarch64")
        self.run(["make", f"-j{self.args.jobs}", "--output-sync=target"], build, "make")
        # Per-attempt staging prevents stale files from a partial install entering the archive.
        stage = self.work / "staging" / self.run_id
        stage.mkdir(parents=True, exist_ok=False)
        self.run(["make", "install", f"DESTDIR={stage}"], build, "install-stage")
        installed = stage / prefix.relative_to("/")
        report = self.verify(installed, doctor)
        report.update(commit=sha, source=str(source), prefix=str(prefix), profile=self.args.profile,
                      built_at=time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                      configure=configure, runtime_dependencies="runtime-dependencies.txt")
        atomic_json(installed / "build-info.json", report)
        artifacts = self.work / "artifacts"
        artifacts.mkdir(exist_ok=True)
        archive = artifacts / f"wine-arm64-{self.args.profile}-{sha[:12]}-{self.run_id}.tar.gz"
        temporary = archive.with_suffix(".partial")
        self.phase = "archive"
        self.status("running")
        self.note(f"Packaging {installed} into {archive}")
        with tarfile.open(temporary, "w:gz", dereference=False) as out:
            out.add(installed, arcname="wine-arm64", filter=self.tar_filter)
        temporary.replace(archive)
        digest = hashlib.sha256()
        with archive.open("rb") as f:
            for block in iter(lambda: f.read(1048576), b""):
                digest.update(block)
        archive.with_suffix(archive.suffix + ".sha256").write_text(f"{digest.hexdigest()}  {archive.name}\n")
        self.phase = "complete"
        self.status("succeeded", artifact=str(archive), installed_tree=str(installed), sha256=digest.hexdigest())
        self.note(f"Success: {archive}")

    def tar_filter(self, member):
        if self.cancelled():
            raise InterruptedError("Stopped during packaging")
        return member

    def verify(self, installed, doctor):
        self.phase = "verify"
        files = {"loader": installed / "bin/wine", "server": installed / "bin/wineserver",
                 "unix_ntdll": installed / "lib/wine/aarch64-unix/ntdll.so",
                 "pe_ntdll": installed / "lib/wine/aarch64-windows/ntdll.dll"}
        report = {"files": {}}
        for name, path in files.items():
            info = verify_pe(path) if name == "pe_ntdll" else elf_info(path)
            if name in ("loader", "server") and info["interpreter"] != doctor["elf"]["interpreter"]:
                raise RuntimeError(f"Installed {name} interpreter differs from glibc probe")
            report["files"][name] = {"path": str(path.relative_to(installed)), **info}
        dependencies = []
        for name in ("loader", "server", "unix_ntdll"):
            dependencies.append(self.run(["readelf", "-d", files[name]], phase="verify-dependencies"))
        (installed / "runtime-dependencies.txt").write_text("\n\n".join(dependencies) + "\n")
        # --version neither initializes WINEPREFIX nor starts a server.
        for name in ("loader", "server"):
            report[name + "_version"] = self.run([files[name], "--version"], phase="verify-runtime", timeout=30)
        return report

    def supervise(self):
        lock = (self.work / "supervisor.lock").open("a")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError(f"Another supervisor owns {self.work}") from None
        try:
            for attempt in range(1, self.args.attempts + 1):
                self.run_id = time.strftime("%Y%m%d-%H%M%S") + f"-{os.getpid()}-{attempt}"
                logs = self.work / "logs"
                logs.mkdir(exist_ok=True)
                with (logs / f"{self.run_id}.log").open("ab") as self.log:
                    self.state.pop("error", None)
                    self.phase = "starting"
                    self.status("running", attempt=attempt, log=self.log.name)
                    try:
                        if self.args.command == "doctor":
                            self.doctor()
                            self.status("succeeded")
                        else:
                            self.build()
                        return 0
                    except InterruptedError as exc:
                        self.note(str(exc))
                        self.status("stopped", error=str(exc))
                        return 130
                    except (OSError, ValueError, RuntimeError) as exc:
                        self.note(f"FAILED: {exc}")
                        self.status("failed", error=str(exc))
                        if attempt == self.args.attempts:
                            return 1
                        self.note(f"Retry in {self.args.retry_delay}s; incremental build is preserved")
                        deadline = time.monotonic() + self.args.retry_delay
                        while time.monotonic() < deadline:
                            if self.cancelled():
                                self.status("stopped")
                                return 130
                            time.sleep(min(0.5, max(0, deadline-time.monotonic())))
                    finally:
                        if hasattr(self, "source_lock"):
                            self.source_lock.close()
            return 1
        finally:
            lock.close()


def positive(value):
    value = int(value)
    if value < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("command", choices=("doctor", "build", "supervise", "status"))
    parser.add_argument("--work-dir", type=Path, default=Path.home() / "wine-arm64-build")
    parser.add_argument("--source", type=Path, help="existing checkout; never pulled or reset")
    parser.add_argument("--repository", default=URL)
    parser.add_argument("--branch", default=BRANCH)
    parser.add_argument("--commit", help="require this full source HEAD SHA; no automatic checkout")
    parser.add_argument("--profile", choices=("termux", "linux"), default="termux")
    gp = Path(os.environ.get("PREFIX", "/data/data/com.termux/files/usr")) / "glibc"
    parser.add_argument("--glibc-prefix", type=Path, default=gp)
    parser.add_argument("--prefix", type=Path, help="final runtime install path (staged, not installed live)")
    parser.add_argument("--jobs", type=positive, default=min(4, os.cpu_count() or 1))
    parser.add_argument("--attempts", type=positive, help="maximum attempts, including first")
    parser.add_argument("--heartbeat", type=positive, default=30)
    parser.add_argument("--retry-delay", type=positive, default=60)
    parser.add_argument("--idle-timeout", type=int, default=1800, help="stop a silent command after N seconds; 0 disables")
    parser.add_argument("--configure-arg", action="append", default=[], help="repeat with =, e.g. --configure-arg=--without-wayland")
    args = parser.parse_args()
    args.attempts = args.attempts or (3 if args.command == "supervise" else 1)
    args.prefix = args.prefix or (args.glibc_prefix / "opt/wine-arm64" if args.profile == "termux" else Path("/opt/wine-arm64"))
    if args.idle_timeout < 0:
        parser.error("--idle-timeout must be >= 0")
    if args.command == "status":
        path = args.work_dir.expanduser().resolve() / "status.json"
        if not path.is_file():
            parser.error(f"No status yet: {path}")
        state = json.loads(path.read_text())
        # An interrupted host may leave an old running record. Verify the lock.
        with (path.parent / "supervisor.lock").open("a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                if state.get("state") == "running":
                    state["state"] = "interrupted"
                    state["note"] = "No supervisor holds the work lock; rerun to resume"
            except BlockingIOError:
                pass
        print(json.dumps(state, indent=2, ensure_ascii=False))
        return 0
    try:
        return Supervisor(args).supervise()
    except (OSError, RuntimeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
