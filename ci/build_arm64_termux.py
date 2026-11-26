#!/usr/bin/env python3
"""Build and supervise ARM64 or ARM64EC Wine for Termux glibc (Python 3.9+)."""
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

from arm64ec_pe import verify_hybrid_pe

URL = "https://github.com/as14725836/wine.git"
BRANCH = "upgrade/dwproton-11.0-17"
ENV_KEYS = ("CC", "CXX", "CFLAGS", "CXXFLAGS", "CPPFLAGS", "LDFLAGS", "CROSSCFLAGS",
            "CROSSLDFLAGS", "PATH", "LD_LIBRARY_PATH", "LIBRARY_PATH", "CPATH",
            "PKG_CONFIG_PATH", "PKG_CONFIG_LIBDIR", "PKG_CONFIG_SYSROOT_DIR",
            "BISON_PKGDATADIR", "M4", "AUTOCONF", "AUTOHEADER", "AUTOM4TE",
            "AUTOM4TE_CFG", "ACLOCAL_PATH", "AC_MACRODIR", "autom4te_perllibdir", "trailer_m4",
            "architecture", "LLVM_MINGW_ROOT", "LLVM_MINGW_VERSION", "LLVM_MINGW_DIGEST",
            "aarch64_CC", "arm64ec_CC", "i386_CC", "x86_64_CC")

# Linked ARM64EC images use AMD64 in the PE COFF header; ARM64EC is the
# object-file machine marker. Keep those expectations separate.
PE_MACHINES = {"aarch64": (0xaa64, "ARM64"), "arm64ec": (0x8664, "AMD64/ARM64EC"),
               "i386": (0x014c, "I386"), "x86_64": (0x8664, "AMD64"),
               "arm64x": (0xaa64, "ARM64/ARM64X")}
PE_OBJECT_MACHINES = {"aarch64": 0xaa64, "arm64ec": 0xa641, "i386": 0x014c,
                      "x86_64": 0x8664}
PE_COMPILER_ALIASES = {"aarch64": ("aarch64-w64-mingw32-clang",),
                       "arm64ec": ("arm64ec-w64-mingw32-clang",),
                       "i386": ("i386-w64-mingw32-clang", "i686-w64-mingw32-clang"),
                       "x86_64": ("x86_64-w64-mingw32-clang",)}


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


def verify_coff_object(path, target):
    data = Path(path).read_bytes()
    if len(data) < 20:
        raise RuntimeError(f"Truncated COFF object: {path}")
    machine = struct.unpack_from("<H", data)[0]
    expected = PE_OBJECT_MACHINES[target]
    if machine != expected:
        raise RuntimeError(f"Expected {target} COFF machine 0x{expected:04x}, "
                           f"got 0x{machine:04x}: {path}")
    return {"machine_id": f"0x{machine:04x}"}


def verify_pe(path, expected_machine=None):
    data = Path(path).read_bytes()
    if data[:2] != b"MZ":
        raise RuntimeError(f"Expected PE executable: {path}")
    off = struct.unpack_from("<I", data, 60)[0]
    if data[off:off + 4] != b"PE\0\0":
        raise RuntimeError(f"Expected PE executable: {path}")
    machine_id = struct.unpack_from("<H", data, off + 4)[0]
    if expected_machine is None:
        expected_machine = "aarch64"
    expected_id, expected_name = PE_MACHINES[expected_machine] if isinstance(expected_machine, str) else expected_machine
    if machine_id != expected_id:
        raise RuntimeError(f"Expected {expected_name} PE (0x{expected_id:04x}), "
                           f"got 0x{machine_id:04x}: {path}")
    return {"machine": expected_name, "machine_id": f"0x{machine_id:04x}"}


class Supervisor:
    def __init__(self, args):
        self.args = args
        self.architecture = args.architecture
        self.work = args.work_dir.expanduser().resolve()
        self.work.mkdir(parents=True, exist_ok=True)
        self.stop = False
        self.state = {"pid": os.getpid(), "started": time.time(), "profile": args.profile,
                      "architecture": self.architecture}
        self.env = os.environ.copy()
        self.pe_compilers = {}
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
        if self.architecture == "arm64ec":
            self._setup_arm64ec_environment(gp)
        self._relocate_autoconf_config()
        self.log = None
        self.phase = "starting"
        self.last_output = time.time()
        signal.signal(signal.SIGINT, self.interrupt)
        signal.signal(signal.SIGTERM, self.interrupt)

    def _setup_arm64ec_environment(self, glibc_prefix):
        root_arg = self.args.llvm_mingw_root
        if root_arg is None or not root_arg.expanduser().is_absolute():
            raise RuntimeError("ARM64EC mode requires an absolute --llvm-mingw-root")
        root = root_arg.expanduser().resolve()
        self.llvm_mingw_root = root
        bindir = root / "bin"
        if not bindir.is_dir():
            raise RuntimeError(f"LLVM-MinGW bin directory does not exist: {bindir}")
        original_path = self.env.get("PATH", "")
        for target in ("aarch64", "arm64ec", "i386", "x86_64"):
            candidates = [bindir / name for name in PE_COMPILER_ALIASES[target]]
            compiler = next((path for path in candidates
                             if path.is_file() and os.access(path, os.X_OK)), None)
            if compiler is None:
                names = ", ".join(PE_COMPILER_ALIASES[target])
                raise RuntimeError(f"Missing LLVM-MinGW {target} compiler in {bindir} (tried {names})")
            # Keep the target-prefixed spelling; clang uses argv[0] to select its driver target.
            compiler = compiler.absolute()
            self.pe_compilers[target] = str(compiler)
            self.env[f"{target}_CC"] = str(compiler)

        # Unix tools must remain native glibc clang, not an LLVM-MinGW PE driver.
        if self.args.profile == "termux":
            unix_cc = glibc_prefix / "bin/clang"
            unix_cxx = glibc_prefix / "bin/clang++"
        else:
            unix_cc = Path(shutil.which("clang", path=original_path) or "")
            unix_cxx = Path(shutil.which("clang++", path=original_path) or "")
        if not unix_cc.is_file() or not unix_cxx.is_file():
            raise RuntimeError(f"ARM64EC mode requires native glibc clang and clang++: {unix_cc}, {unix_cxx}")
        # Preserve clang++ driver mode and Termux's driver-name configuration.
        self.env["CC"] = str(unix_cc.absolute())
        self.env["CXX"] = str(unix_cxx.absolute())
        path_parts = [str(bindir)]
        glibc_bin = glibc_prefix / "bin"
        if glibc_bin.is_dir():
            path_parts.append(str(glibc_bin))
        if original_path:
            path_parts.append(original_path)
        self.env["PATH"] = os.pathsep.join(path_parts)
        self.env["LLVM_MINGW_ROOT"] = str(root)

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
        compiler = self.run(shlex.split(self.env["CC"]) + ["--version"], phase="compiler-version")
        pe = probe / "pe.c"
        pe.write_text("void mainCRTStartup(void) {}\n")
        if self.architecture == "arm64ec":
            pe_reports = {}
            compiler_versions = {}
            reports = self.work / "pe-reports"
            reports.mkdir(exist_ok=True)
            tools = {name: self.llvm_mingw_root / "bin" / name
                     for name in ("llvm-readobj", "llvm-dlltool", "llvm-nm")}
            for name, path in tools.items():
                if not path.is_file() or not os.access(path, os.X_OK):
                    raise RuntimeError(f"Missing executable LLVM-MinGW {name}: {path}")
            for target in ("aarch64", "arm64ec", "i386", "x86_64"):
                pe_cmd = [self.pe_compilers[target]]
                compiler_versions[target] = self.run(pe_cmd + ["--version"],
                                                     phase=f"compiler-version-{target}", timeout=30)
                obj = probe / f"pe-{target}.obj"
                output = probe / f"pe-{target}.exe"
                # Probe the actual prefixed driver's defaults, without forcing a target.
                self.run(pe_cmd + ["-c", str(pe), "-o", str(obj)],
                         phase=f"probe-coff-{target}", timeout=60)
                object_info = verify_coff_object(obj, target)
                self.run(pe_cmd + ["-fuse-ld=lld", "-nostdlib", str(obj),
                                   "-Wl,-entry:mainCRTStartup", "-Wl,-subsystem:console",
                                   "-o", str(output)], phase=f"probe-pe-{target}", timeout=60)
                pe_reports[target] = {"object": object_info, "image": verify_pe(output, target)}
                evidence = self.run([tools["llvm-readobj"], "--file-headers", "--coff-load-config", output],
                                    phase=f"probe-pe-headers-{target}", timeout=30)
                (reports / f"probe-{target}.txt").write_text(evidence + "\n")
            ec_def, native_def = probe / "ec.def", probe / "native.def"
            ec_def.write_text("LIBRARY test.dll\nEXPORTS\n    func\n")
            native_def.write_text("LIBRARY test.dll\nEXPORTS\n    otherfunc\n")
            archive = probe / "dual-def.lib"
            self.run([tools["llvm-dlltool"], "-m", "arm64ec", "-d", ec_def,
                      "-N", native_def, "-l", archive], phase="probe-dlltool-dual-def", timeout=30)
            armap = self.run([tools["llvm-nm"], "--print-armap", archive],
                             phase="probe-dlltool-armap", timeout=30)
            (reports / "dual-def-armap.txt").write_text(armap + "\n")
            maps = {"native": set(), "ec": set()}
            current = None
            for line in armap.splitlines():
                if line.strip() == "Archive map":
                    current = "native"
                elif line.strip() == "Archive EC map":
                    current = "ec"
                elif not line.strip():
                    current = None
                elif current and " in " in line:
                    maps[current].add(line.split(" in ", 1)[0].strip())
            expected = {"native": {"__imp_otherfunc", "otherfunc"},
                        "ec": {"#func", "__imp_aux_func", "__imp_func", "func"}}
            for kind, symbols in expected.items():
                if not symbols.issubset(maps[kind]) or symbols & maps["ec" if kind == "native" else "native"]:
                    raise RuntimeError(f"Incorrect dual-DEF {kind} archive map: {sorted(maps[kind])}")
            # Ordinary ARM64 import libraries must not receive ARM64EC-only -N.
            self.run([tools["llvm-dlltool"], "-m", "arm64", "-d", native_def,
                      "-l", probe / "native.lib"], phase="probe-dlltool-arm64", timeout=30)
            result = {"architecture": self.architecture, "elf": info, "glibc_version": version,
                      "pe": pe_reports, "compiler": compiler, "pe_compilers": compiler_versions,
                      "llvm_mingw_root": str(self.llvm_mingw_root),
                      "dual_def_maps": {kind: sorted(symbols) for kind, symbols in maps.items()}}
        else:
            pe_cmd = shlex.split(self.env.get("aarch64_CC", "clang"))
            self.run(pe_cmd + ["--no-default-config", "-target", "aarch64-windows", "-fuse-ld=lld",
                              "-nostdlib", str(pe), "-Wl,-entry:mainCRTStartup", "-Wl,-subsystem:console",
                              "-o", str(probe / "pe.exe")], phase="probe-pe", timeout=60)
            pe_info = verify_pe(probe / "pe.exe")
            result = {"architecture": self.architecture, "elf": info, "glibc_version": version,
                      "pe": pe_info, "compiler": compiler}
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
        architectures = "aarch64,arm64ec,i386" if self.architecture == "arm64ec" else "aarch64"
        configure = [str(source / "configure"), "--enable-option-checking=fatal",
                     f"--prefix={prefix}", f"--exec-prefix={prefix}", f"--enable-archs={architectures}",
                     "--disable-tests", "--disable-win16", "--without-oss"]
        if self.architecture == "arm64ec":
            configure.append("--with-mingw=llvm-mingw")
        for arg in self.args.configure_arg:
            if arg.startswith(("--prefix", "--exec-prefix", "--bindir", "--libdir", "--enable-archs",
                               "--host", "--build", "--with-mingw", "--without-mingw", "--disable-win64")):
                raise RuntimeError(f"Option conflicts with {self.architecture} ARM64 layout: {arg}")
        configure += self.args.configure_arg
        if not (source / "configure").is_file():
            self.run(["sh", "./autogen.sh"], source, "autogen")
        config = {"source": str(source), "commit": sha, "configure": configure,
                  "source_digest": self.source_fingerprint(source),
                  "profile": self.args.profile, "architecture": self.architecture, "doctor": doctor,
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
        expected_archs = architectures.split(",")
        if sorted(archs.split()) != sorted(expected_archs):
            raise RuntimeError(f"Unexpected PE_ARCHS={archs!r}, expected {expected_archs}")
        self.run(["make", f"-j{self.args.jobs}", "--output-sync=target"], build, "make")
        # Per-attempt staging prevents stale files from a partial install entering the archive.
        stage = self.work / "staging" / self.run_id
        stage.mkdir(parents=True, exist_ok=False)
        self.run(["make", "install", f"DESTDIR={stage}"], build, "install-stage")
        installed = stage / prefix.relative_to("/")
        report = self.verify(installed, doctor)
        report.update(commit=sha, source=str(source), prefix=str(prefix), profile=self.args.profile,
                      architecture=self.architecture,
                      built_at=time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                      configure=configure, runtime_dependencies="runtime-dependencies.txt")
        atomic_json(installed / "build-info.json", report)
        artifacts = self.work / "artifacts"
        artifacts.mkdir(exist_ok=True)
        package = "wine-arm64ec" if self.architecture == "arm64ec" else "wine-arm64"
        archive = artifacts / f"{package}-{self.args.profile}-{sha[:12]}-{self.run_id}.tar.gz"
        temporary = archive.with_suffix(".partial")
        self.phase = "archive"
        self.status("running")
        self.note(f"Packaging {installed} into {archive}")
        with tarfile.open(temporary, "w:gz", dereference=False) as out:
            out.add(installed, arcname=package, filter=self.tar_filter)
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
        if self.architecture == "arm64ec":
            files["i386_ntdll"] = installed / "lib/wine/i386-windows/ntdll.dll"
        report = {"files": {}}
        for name, path in files.items():
            if name in ("pe_ntdll", "i386_ntdll"):
                info = verify_pe(path, "i386" if name == "i386_ntdll" else "aarch64")
            else:
                info = elf_info(path)
            if name in ("loader", "server") and info["interpreter"] != doctor["elf"]["interpreter"]:
                raise RuntimeError(f"Installed {name} interpreter differs from glibc probe")
            report["files"][name] = {"path": str(path.relative_to(installed)), **info}
        if self.architecture == "arm64ec":
            validation = verify_hybrid_pe(files["pe_ntdll"])
            reports = self.work / "pe-reports"
            reports.mkdir(exist_ok=True)
            atomic_json(reports / "installed-validation.json", validation)
            atomic_json(installed / "hybrid-validation.json", validation)
            report["hybrid_validation"] = validation
            if not validation["ok"]:
                raise RuntimeError(f"Installed ARM64X ntdll validation failed: {validation['errors']}")
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
    parser.add_argument("--architecture", choices=("native", "arm64ec"), default="native",
                        help="native ARM64 or ARM64X/ARM64EC with i386 WoW64")
    parser.add_argument("--llvm-mingw-root", type=Path,
                        help="absolute LLVM-MinGW root; required for arm64ec mode")
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
    install_name = "wine-arm64ec" if args.architecture == "arm64ec" else "wine-arm64"
    args.prefix = args.prefix or ((args.glibc_prefix / "opt" / install_name)
                                  if args.profile == "termux" else Path("/opt") / install_name)
    if args.architecture == "native" and args.llvm_mingw_root is not None:
        parser.error("--llvm-mingw-root requires --architecture arm64ec")
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
