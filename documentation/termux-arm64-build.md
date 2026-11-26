# Termux 上原生 ARM64 glibc Wine 构建

首选入口是[手动 GitHub Actions 工作流](../.github/workflows/build-termux-arm64.yml)：在仓库的 ARM64 Linux runner 上，使用官方 Termux glibc 工具链构建 Wine 的 AArch64 Unix 与 ARM64 PE 部分。[监督脚本](../ci/build_arm64_termux.py) 负责完整构建、重试、日志、心跳、状态和暂存产物，需要 Python 3.9 或更新版本。目标是原生 ARM64，不依赖 Box64 或 ARM64EC。

**完整远端构建已成功：[Actions 第 7 次运行](https://github.com/as14725836/wine/actions/runs/45756054226)在 GitHub ARM64 Linux runner 上使用官方 Termux glibc 工具链完成全量编译、暂存安装、验证和打包。已生成完整 Wine 二进制包，未做 Android/Termux 真机运行验证。按“不要在本地编译，在仓库编译构建”的要求，本地仅做静态检查；后文设备构建命令仅作可选参考，`doctor` 会编译和运行小型探针。**

## 仓库端构建：GitHub Actions

仓库中的构建文件是：

- [工作流](../.github/workflows/build-termux-arm64.yml)。
- [监督脚本](../ci/build_arm64_termux.py)。
- [CI 依赖准备器](../ci/prepare_termux_glibc_ci.py)。
- [官方包版本与 SHA256 锁](../ci/termux-glibc-aarch64.lock.json)。
- [源码前置补丁](../ci/patches/dwproton-arm64-prerequisites.patch)。
- 本指南。

基础构建文件位于 `as14725836/wine` 的 `upgrade/dwproton-11.0-17` 分支。当前默认分支 `master` 尚未注册此工作流，向升级分支直接调用 `workflow_dispatch` 已返回 404。执行分支 `ci/termux-arm64-full-build` 因此为此工作流增加了仅限自身分支、仅限构建文件变更的 `push` 触发器，用于首次构建及修复后重试，无需修改默认分支。仓库现有 WoW64/ARM64EC 的 push 分支过滤器均不匹配此执行分支。不要运行仓库原有会发布 Release 的工作流来代替它。

待维护者将工作流定义加入默认分支后，也可在 **Actions → Termux glibc ARM64 full build → Run workflow** 中选择包含构建文件的分支手动运行。执行分支上的新工作流支持上述限定 push 和手动触发，权限为 `contents: read`，不发布 Release、不改 tag。构建基础设施取自所选分支；Wine 源码另行 checkout 到固定的 `6f1e28b249b073e36b5f68eea42f2631163b091f`，核对 SHA 后应用随附五文件补丁，其中 SQLite 内存屏障显式识别 Windows 目标下的 Clang，使用其 `__sync_synchronize()`，避免走 Wine ARM64 头文件未声明的 `_ReadWriteBarrier()` 分支。分开检出避免把基础设施分支的变动误当成固定 Wine 源码；补丁只应用在该 runner 的源码检出目录。

工作流使用 `ubuntu-24.04-arm`，最长 330 分钟，并发作业按分支排队，不自动取消正在运行的任务。它通过 Ubuntu apt 安装构建辅助工具，通过锁文件下载 79 个官方 Termux glibc AArch64/架构无关包（361,253,024 字节，约 361 MB），逐包核对大小、SHA256 和包元数据，然后解包到精确前缀 `/data/data/com.termux/files/usr/glibc`。Wine 使用这些官方 Termux glibc 库和工具链构建；LLVM 启动所需的旧 libxml2 ABI 另按下文补齐。准备器 `--install` 仅允许 GitHub-hosted Linux ARM64 环境，拒绝覆盖已有 Termux prefix；它不是给手机安装软件的脚本。锁文件固定内容，若源站移除旧版本归档会直接失败，不会静默升级或替换校验和。

解包不执行 Debian 维护脚本。闭包中唯一的外部依赖例外是配置包 `resolv-conf`，显式用 runner 的 resolver 配置满足；不引入 Bionic 可执行文件。首次远端执行发现 GCC 包使用双斜杠绝对链接，准备器已修正路径规范化；第二次运行确认 LLVM 19 需要 `libxml2.so.2`，但当前官方 libxml2 2.15.4 仅提供 `.so.16`。准备器因此仅在 GitHub runner 上用 Ubuntu GCC 引导构建固定的 libxml2 2.13.6（[历史 Termux 配方](https://github.com/termux-pacman/glibc-packages/blob/16a5e6853837f8c67248bc72c6893aba8d2acb99/gpkg/libxml2/build.sh)，[上游 SHA256](https://download.gnome.org/sources/libxml2/2.13/libxml2-2.13.6.sha256sum)：`f453480307524968f7a04ec65e64f2a83a825973bcd260a2e7691be82ae70c96`）。只构建共享库目标，禁用外部可选依赖，校验 AArch64、真实 `.so.2` SONAME、LLVM 所需符号版本与仅 glibc 的 libc/libm/动态加载器依赖后，将兼容库并排放入前缀；保留锁定包的 `.so.16`、头文件及 pkg-config，不用改名伪装 ABI。此库用于启动 Termux 编译器，不随 Wine 归档捆绑。构建日志和源码/产物哈希一并上传；宿主 GCC 不用于编译 Wine。全量编译日志还确认 `amd_ags_x64` 无条件需要 DRM 头文件和库，而 PE 导入库生成需要 `llvm-dlltool`；锁中已加入真实的 `libdrm-glibc`、`llvm-glibc` 及依赖闭包。`libllvm-glibc` 只提供 LLVM 运行库，不能替代提供工具的 `llvm-glibc`，也无需伪造 `dlltool` 别名。随后准备器验证必需的 DRM 文件与 clang/lld/llvm-dlltool 的 ELF interpreter、共享库解析均属于 glibc prefix。clang/lld 执行版本检查；llvm-dlltool 则根据最小 `.def` 文件，以 `-m arm64` 实际生成导入库并检查归档签名（该版本的无输入 `--version` 会返回非零，不能用作启动成功判据）。结果写入 `toolchain-checks.txt`；缺文件、路径错误、工具无法启动或导入库生成失败均使任务失败。整个进程树不设置 glibc `LD_LIBRARY_PATH`，避免污染 Ubuntu Python、make、git。Unix 链接通过 `LDFLAGS=-fuse-ld=lld` 选择官方 LLD，监督器再追加精确的 glibc loader 与 rpath；PE 编译器也固定为同一官方 clang。实际工具、链接器、启动文件和库搜索路径会记录在 `tool-paths.txt`。

随后监督器执行 glibc/PE 探针、autogen（若需要）、configure、全量 `make`、`make install DESTDIR=...`、ELF/PE 架构校验、暂存 `wine --version` / `wineserver --version`、打包与 SHA256。它不只构建若干 DLL。配置要求 X11、FreeType、Fontconfig、GnuTLS；为避免带入未锁定的服务或媒体依赖，当前工作流关闭 Wayland、PulseAudio、GStreamer 和 FFmpeg。其他可选组件以 configure 输出为准，不承诺 Vulkan、游戏或多媒体兼容。

监督器使用 4 个编译作业，最多尝试 3 次，心跳 30 秒，失败间隔 60 秒，命令无输出上限 1800 秒。一次 workflow run 内复用增量构建；GitHub 的 **Re-run jobs** 使用新 runner，不保留上次完整 build 树。取消工作流或达到作业时限后，不保证最后的日志上传步骤仍能完成，也没有跨运行的常驻监督服务。

在运行页面查看步骤日志、心跳和 Summary。正常结束时：

- 成功的 `wine-termux-arm64-<run_id>-<attempt>` artifact 包含完整 Wine `.tar.gz` 及其 `.sha256`。
- 成功或失败均尝试上传 `wine-termux-arm64-diagnostics-<run_id>-<attempt>`：锁文件、基础设施提交号、bootstrap 日志、libxml2 兼容库的构建日志与哈希记录、工具链路径/加载器报告、监督日志、JSON 状态和构建指纹、源码差异、configure 日志等。若任务在更早阶段失败，相应文件可能尚未生成。
- artifacts 保留 14 天；需要长期保存时应自行下载。日志和 JSON 中的 runner 临时路径只供诊断，不是手机安装路径。

### 已成功的构建与下载

[运行 #7](https://github.com/as14725836/wine/actions/runs/45756054226)于 2026-11-26 04:45 UTC 完成，结论为 `success`。构建基础设施提交是 `985c651ea8088e4c0f14356ed5c8d3848ffc6159`，Wine 源码是前述固定提交加五文件补丁。

- [完整 Wine 产物](https://github.com/as14725836/wine/actions/runs/45756054226/artifacts/15087533558)：`wine-termux-arm64-45756054226-1`，内含 `.tar.gz` 和 `.sha256`。
- [诊断产物](https://github.com/as14725836/wine/actions/runs/45756054226/artifacts/15087892458)：`wine-termux-arm64-diagnostics-45756054226-1`。
- Wine 压缩包：`wine-arm64-termux-6f1e28b249b0-20261126-043705-8310-1.tar.gz`，178,476,734 字节（约 170.2 MiB）。
- 压缩包 SHA256：`38421d4d65f5c4ac4a669b3ac868e085173d19b8608725bd3c3fd66f2e22d6a1`。
- runner 实际执行暂存程序得到 `wine-11.0 (CachyOS)` 和 `Wine 11.0`。这些是版本检查，不是 Windows 应用运行测试。

上述 artifacts 的到期时间是 **2026-12-10 04:44 UTC**；请在到期前登录 GitHub 下载并自行保存。GitHub 下载得到的是外层 ZIP，须先解出内部的 `.tar.gz` 和 `.sha256`，再按下节安装。ZIP 与内部压缩包的 SHA256 不同。

下载后已独立核对压缩包 SHA256、归档路径和链接、全部 ELF/PE 文件头、核心运行库搜索路径及构建元数据：归档含 40 个 AArch64 ELF、780 个 ARM64 PE、50 个 NE 字体资源，以及 10 个 WinMD 元数据文件。后者是 WIDL 固定输出的 I386 PE32/CLI 元数据容器，不是 x86 可执行模块；仅对十个精确路径在核对零入口点、元数据流边界、零方法体 RVA、无原生互操作/数据表后单独接受，未放宽其他 PE 的 ARM64 要求。核心 loader/server 的 interpreter 均为 `/data/data/com.termux/files/usr/glibc/lib/ld-linux-aarch64.so.1`。这些本地检查没有执行归档中的二进制。

使用官方 Termux glibc 工具链在 GitHub ARM64 Linux runner 完整构建已经通过；Android 内核、权限、图形和音频服务仍需真机验收。

## 在 Termux 安装远端构建产物

目标是标准包名的 AArch64 Termux，固定 glibc prefix 为 `/data/data/com.termux/files/usr/glibc`。其他包名、用户目录或 prefix 不可直接套用此产物。先启用官方 glibc 源，并安装对应运行库：

```sh
pkg install glibc-repo
pkg update
pkg install glibc-runner freetype-glibc fontconfig-glibc \
  libx11-glibc libxext-glibc libxrender-glibc libxi-glibc \
  libxrandr-glibc libxcursor-glibc libxinerama-glibc \
  libxcomposite-glibc libxfixes-glibc libgnutls-glibc \
  libjpeg-turbo-glibc libpng-glibc alsa-lib-glibc dbus-glibc \
  libglvnd-glibc libdrm-glibc
```

归档只包含 Wine，不捆绑 glibc 依赖库或 CI 的 libxml2 编译器兼容库。CI 的精确依赖版本见[锁文件](../ci/termux-glibc-aarch64.lock.json)；设备源可能更新，上述安装命令不承诺与锁文件版本完全相同。

在已经从 ZIP 解出 `.tar.gz` 和 `.sha256` 的目录执行以下命令。每步失败即停止；已有 Wine 安装时先自行备份并处理，命令拒绝覆盖现有目录：

```sh
(
  set -eu
  test "$PREFIX" = /data/data/com.termux/files/usr
  ARCHIVE=wine-arm64-termux-6f1e28b249b0-20261126-043705-8310-1.tar.gz
  sha256sum -c "$ARCHIVE.sha256"
  DEST="$PREFIX/glibc/opt"
  if [ -e "$DEST/wine-arm64" ] || [ -L "$DEST/wine-arm64" ]; then
    echo "目标已存在，请先备份并处理：$DEST/wine-arm64" >&2
    exit 1
  fi
  mkdir -p "$DEST"
  tar -xzf "$ARCHIVE" -C "$DEST"
  "$DEST/wine-arm64/bin/wine" --version
  "$DEST/wine-arm64/bin/wineserver" --version
)
```

安装位置为 `$PREFIX/glibc/opt/wine-arm64`。不要将 glibc 库目录全局写入 Termux 的 `LD_LIBRARY_PATH`；二进制已记录固定的 glibc loader 与运行库搜索路径。上面的版本检查不会初始化 WINEPREFIX。使用窗口程序还需要另行配置可用的 X11 服务和 `DISPLAY`；本次构建不包含图形服务部署或真机应用验收。

## 可选：在目标 Termux 设备构建

以下操作供另行选择设备构建时使用，不是仓库 Actions 的本地前置步骤。

### 安装依赖

先启用 Termux glibc 包源，再安装 runner 和 glibc 版编译器：

```sh
pkg install glibc-repo
pkg update
pkg install glibc-runner clang-glibc llvm-glibc libdrm-glibc freetype-glibc
```

脚本检查的命令还包括 Git、make、Perl、Python 3、Autoconf/`autoreconf`、Bison、Flex、pkg-config、clang、LLD 和 `readelf`。Termux 常规构建工具可这样安装：

```sh
pkg install git make perl python autoconf bison flex pkg-config llvm lld binutils
```

这里的包名是 Termux 的包名，不是命令名：当前 Termux `binutils` 配方会把冲突的 GNU `readelf` 改名为 `greadelf`，所以不能据此保证脚本所需的无前缀 `readelf`；应安装能提供 LLVM `readelf` 的 `llvm` 包，并用 `command -v readelf` 和 `readelf --version` 实际确认。`autoconf` 提供 `autoreconf`；glibc 编译器包叫 **`clang-glibc`**，但可执行文件仍叫 `clang`、`clang++`，位于 `$PREFIX/glibc/bin/`。其 glibc 运行时及链接器依赖由包配方声明。脚本会把该目录加到 PATH 前端，并要求 `CC` 指向其中的 `clang`；不能用普通 Termux Bionic clang 代替。Termux 配置还会将 pkg-config 搜索目录限定为该 glibc prefix 下的 `lib/pkgconfig` 和 `share/pkgconfig`，并清空继承的 `PKG_CONFIG_PATH`、`PKG_CONFIG_SYSROOT_DIR`，避免意外发现 Bionic 库。

`freetype-glibc` 同时提供 FreeType 头文件、可链接的库和 `freetype2.pc`，无需另装 `-dev` 包。该 Wine 分支默认要求 FreeType；缺失时 configure 会报错，不应把禁用字体当作常规修复。需要 X11 窗口及常见字体、图像、TLS、音频功能时，可继续安装以下 glibc 依赖；具体启用情况仍以 configure 输出为准：

```sh
pkg install fontconfig-glibc libx11-glibc libxext-glibc libxrender-glibc \
  libxi-glibc libxrandr-glibc libxcursor-glibc libxinerama-glibc \
  libxcomposite-glibc libxfixes-glibc libgnutls-glibc libjpeg-turbo-glibc \
  libpng-glibc alsa-lib-glibc libpulse-glibc dbus-glibc libglvnd-glibc
```

这些包名已在官方 AArch64 Debian glibc 包索引中核对；也直接检查了官方 `freetype-glibc_2.14.3_aarch64.deb` 的头文件、库和 pkg-config 元数据。`libpulse-glibc` 客户端依赖普通 Termux 的 `pulseaudio` 服务端，这不表示可以用 Bionic 客户端库参与 Wine 链接。包索引和归档检查不是对实际设备、Termux 版本或图形/音频服务可用性的实测。若 `pkg` 找不到包，请检查 Termux 官方源配置、索引更新及设备架构，不要换用 Bionic 开发库来绕过。

## 源码与首次检查

从交付包解压后的根目录运行命令（包含 `ci/`、`documentation/`）。请将整个工具包放在新 Wine 源码树之外。默认源码目录为工作目录下的 `source/`：该目录不存在时，脚本会从默认仓库 `https://github.com/as14725836/wine.git` 以单分支方式克隆默认分支 `upgrade/dwproton-11.0-17`。已有 `source/` 则直接使用；不会自动 fetch、pull、checkout、reset，也不会在重试时改变源码。传入 `--source DIR` 时，DIR 必须是已经存在的 Wine 源码检出目录；显式给出的不存在目录不会替你克隆。`--repository` 和 `--branch` 只决定新克隆来源与分支。工作目录必须位于源码树之外：`--work-dir` 不能是源码目录本身，也不能是源码目录的子目录；默认的 `work/source/` 仍然有效，因为它是源码树的父目录。

`--commit` 必须是完整 Git SHA，只校验当前 `HEAD` 是否相同，**不会切换到该提交**。本交付针对 `upgrade/dwproton-11.0-17` 的提交 `6f1e28b249b073e36b5f68eea42f2631163b091f`。为避免分支前移造成构建内容变化，请在新的目录准备该提交，把随附补丁检查并应用到源码，再把这份脚本放在源码树之外运行：

```sh
TOOLKIT="$(pwd)"
SRC="$HOME/src/wine-dwproton"
WORK="$HOME/wine-arm64-build"
mkdir -p "$HOME/src"
git clone --single-branch --branch upgrade/dwproton-11.0-17 \
  https://github.com/as14725836/wine.git "$SRC"
git -C "$SRC" checkout --detach 6f1e28b249b073e36b5f68eea42f2631163b091f

git -C "$SRC" rev-parse HEAD
PATCH="$TOOLKIT/ci/patches/dwproton-arm64-prerequisites.patch"
git -C "$SRC" apply --check "$PATCH"
git -C "$SRC" apply "$PATCH"

python3 "$TOOLKIT/ci/build_arm64_termux.py" doctor \
  --source "$SRC" --commit 6f1e28b249b073e36b5f68eea42f2631163b091f \
  --work-dir "$WORK"
python3 "$TOOLKIT/ci/build_arm64_termux.py" supervise \
  --source "$SRC" --commit 6f1e28b249b073e36b5f68eea42f2631163b091f \
  --work-dir "$WORK" --jobs 4
```

每条命令成功后再执行下一条；`git rev-parse HEAD` 必须输出上面的完整 SHA。补丁应只应用一次；`git apply --check` 若失败就先停下检查源码版本或已有修改，不要强制覆盖。上游新克隆默认不会带这些本地补丁，因此仅运行不带 `--source` 的默认克隆流程不等价于本交付源码。

随附补丁只涉及以下五个文件：

- `dlls/mfplay/player.c`：移除错误添加的 `IMFPMediaPlayer::SetVideoWindow` 实现和虚表项，恢复与官方 39 槽接口一致的顺序。官方接口有 `GetVideoWindow`，没有 `SetVideoWindow`；后者属于其他接口。`include/mfplay.idl` 保持不变，不要给它添加该方法来绕过编译错误。
- `include/wine/server_protocol.h`：按该提交的 `server/protocol.def` 重新生成，补齐对应 ESYNC 协议定义，协议版本从 935 更新到 936。
- `dlls/icuin/icuin.spec` 与 `dlls/icuuc/icuuc.spec`：分别规范化 416 和 542 项转发导出的生成格式，保留名称、序号、顺序和转发目标；这不等于已证明 ICU 的 ARM64 运行时 ABI 兼容。
- `libs/sqlite3/sqlite3.c`：让内存屏障分支识别 `__clang__`，在 ARM64 Windows PE 编译时使用 `__sync_synchronize()`，避免调用该架构头文件中未声明的 `_ReadWriteBarrier()`。

补丁的生成文件已用对应生成器复现核对；`mfplay` 修正曾定位到实际编译报错，并已在 GitHub Actions 的远端完整构建中通过。补丁适用性检查与远端 CI 成功都不代表已在实际设备上运行。

可用 `python3 "$TOOLKIT/ci/build_arm64_termux.py" --help` 查看全部选项。默认 glibc prefix 是 `$PREFIX/glibc`（缺少 `PREFIX` 时脚本回退到 `/data/data/com.termux/files/usr/glibc`），默认最终运行时 prefix 是 `$PREFIX/glibc/opt/wine-arm64`。配置阶段会把 `--prefix` 与 `--exec-prefix` 都显式设为最终运行时 prefix，避免 Autoconf 默认的 Android 子目录改变可执行文件安装布局。`doctor` 会验证 AArch64 主机、工具、glibc loader、可执行的 glibc 探针和 ARM64 PE 编译探针，并写入 `doctor.json`。它不是完整 Wine 构建或图形能力测试。

## 监督、重试与停止

前台运行 `supervise` 时，状态心跳默认每 30 秒输出；命令完整输出同时写到 `logs/<run_id>.log`。默认最多尝试 3 次（包含首次），失败后间隔 60 秒重试；增量 build 目录会保留。`doctor` 与单次 `build` 默认各只尝试 1 次。可通过 `--attempts N` 和 `--retry-delay SEC` 调整监督重试，`--idle-timeout SEC` 默认 1800 秒无命令输出即中止当前命令，设为 `0` 可禁用。心跳仅表示监督进程仍在运行，不代表编译有进展。

需要后台运行时，可使用 `nohup` 并把控制台输出另存；完整构建日志仍在工作目录的 `logs/`。下面假设当前目录仍是解压后的工具包根目录，源码已按前文固定到指定提交并应用补丁。新开终端时先进入工具包根目录，再重新设置这些变量：

```sh
TOOLKIT="$(pwd)"
SRC="$HOME/src/wine-dwproton"
WORK="$HOME/wine-arm64-build"
mkdir -p "$WORK"
nohup python3 "$TOOLKIT/ci/build_arm64_termux.py" supervise \
  --source "$SRC" --commit 6f1e28b249b073e36b5f68eea42f2631163b091f \
  --work-dir "$WORK" --jobs 4 \
  >> "$WORK/supervisor.out" 2>&1 < /dev/null &
echo $! > "$WORK/supervisor.pid"
```

`nohup` 只能处理终端挂断，不能保证进程躲过 Android 后台限制、系统杀进程或设备重启。可按设备设置允许 Termux 后台运行，并按需使用 Termux 的唤醒锁；设备重启后仍需重新启动监督命令。GitHub Actions 执行有限时长的远端构建任务；本交付没有启动跨工作流常驻守护服务或设备后台服务。

创建 `$WORK/STOP` 可请求协作停止；也可向监督进程发送 SIGINT 或 SIGTERM：

```sh
touch "$WORK/STOP"
python3 "$TOOLKIT/ci/build_arm64_termux.py" status --work-dir "$WORK"
```

监督器会终止当前命令进程组（先 SIGTERM，最多等待 10 秒后再 SIGKILL），正常处理停止请求后状态变为 `stopped`，退出码为 130。`touch` 返回不等于已经停止，应重复查询 `status`，确认进程已退出后再恢复。停止不会删除源码、增量构建目录或日志。恢复时仅移除停止标记，并沿用原参数：

```sh
rm -f -- "$WORK/STOP"
python3 "$TOOLKIT/ci/build_arm64_termux.py" supervise \
  --source "$SRC" --commit 6f1e28b249b073e36b5f68eea42f2631163b091f \
  --work-dir "$WORK" --jobs 4
```

随时查看最近一次状态：

```sh
python3 "$TOOLKIT/ci/build_arm64_termux.py" status --work-dir "$WORK"
```

`status.json` 保存状态、阶段、PID、尝试次数、日志路径及成功时的产物信息。若上次异常退出留下 `running`，而监督锁已释放，`status` 会显示为 `interrupted`，提示可重新运行以续做；它不会改写该状态文件。相同工作目录不允许并发监督任务。

## 指纹、产物与解包

工作目录包含 `build/` 增量构建树、`build-config.json` 配置指纹、`configured.json`、`doctor.json`、`logs/`、每次尝试独立的 `staging/<run_id>/`，以及 `artifacts/`。若源码缺少 `configure`，脚本先运行 `autogen.sh`，再计算 `source_digest`。该摘要包含 `git diff --binary HEAD` 的完整 tracked 差异、标准 untracked 文件（排除 `__pycache__` 和监督锁），以及始终纳入的被 Git 忽略的 `configure`（含文件模式与内容）。指纹还记录源码路径及 SHA、configure 参数、profile、doctor 结果和一组影响构建的环境变量。源码、工具链探测结果、配置或受跟踪环境值不一致时构建会失败并保留旧工作目录；按错误提示使用新的 `--work-dir`，不要手工删改指纹来强行复用。

成功归档名为 `artifacts/wine-arm64-<profile>-<sha12>-<run_id>.tar.gz`，旁边有 `.tar.gz.sha256` 校验文件。每次尝试安装到新的 staging 子目录，避免失败尝试留下的半成品混入归档；构建不会直接安装或覆盖活动 prefix。归档内部固定顶层目录名为 `wine-arm64/`，但二进制使用构建时设定的绝对 glibc loader/rpath，因此不能当作可随意搬移的目录。默认 prefix 的 basename 正好是 `wine-arm64`，可直接解到其父目录；自定义 `--prefix` 时，应先解到空临时目录，再把临时目录下 `wine-arm64/` 的内容部署到**确切的原配置 prefix**：

```sh
ART="$HOME/wine-arm64-build/artifacts"
ARCHIVE="$(ls -t "$ART"/wine-arm64-termux-*.tar.gz | head -n 1)"
(cd "$ART" && sha256sum -c "$(basename "$ARCHIVE").sha256")
DEST="$PREFIX/glibc/opt"
mkdir -p "$DEST"
tar -xzf "$ARCHIVE" -C "$DEST"
```

上述默认 prefix 解包后应得到 `$PREFIX/glibc/opt/wine-arm64/`。如果构建时通过 `--prefix` 设了其他绝对路径，归档中的固定 basename 仍是 `wine-arm64`，所以不要直接解到自定义 prefix 的父目录来推断部署位置；部署前自行确认目标目录不会覆盖现有文件。

构建验证检查若干 ELF/PE 文件架构、loader、依赖记录，并运行暂存的 `wine --version` 与 `wineserver --version`；不会初始化 WINEPREFIX。**本任务没有在实际 Termux 设备上完成构建实测**。这些检查不证明 Wine GUI、Wayland/X11、图形驱动、音频/多媒体设备或任意 Windows 程序可用；不能据此承诺图形或驱动兼容性。

包源依据：

- [Termux glibc packages README](https://github.com/termux/glibc-packages#readme)：启用 `glibc-repo` 并安装 `glibc-runner`。
- [`clang-glibc` 构建配方](https://github.com/termux/glibc-packages/blob/main/gpkg/clang/build.sh)：包名与 glibc 编译器依赖。
- [Termux `pkg-config` 配方](https://github.com/termux/termux-packages/blob/master/packages/pkg-config/build.sh)：常规构建工具包名。
- [Termux `binutils` 配方](https://github.com/termux/termux-packages/blob/master/packages/binutils/build.sh)：其安装后步骤对冲突工具（包括 `readelf`）改用 `g` 前缀；这也是不能把 `binutils` 单独当作无前缀 `readelf` 提供者的依据。
- [官方 AArch64 glibc APT 包索引](https://packages.termux.dev/apt/termux-glibc/dists/glibc/stable/binary-aarch64/Packages)：上述 glibc 包名和依赖的核对来源；索引可能更新，以设备上刷新后的包源为准。
- [官方 FreeType glibc 归档](https://packages.termux.dev/apt/termux-glibc/pool/stable/f/freetype-glibc/freetype-glibc_2.14.3_aarch64.deb)：核对了头文件、可链接库和 `freetype2.pc`；归档 SHA256 为 `ffa8d63d8d0e4720422eb882ff3a09f1f31dc0633b5eac41b7f1c5cc7a668313`，与索引一致。

## 配置范围与验证边界

脚本还保留 `--profile linux`，用于原生 AArch64 glibc Linux 的独立配置；本指南使用默认的 `termux` profile。Linux 上的检查也不能替代 Termux glibc、Android 内核和用户空间集成测试。本任务已按要求停止本地构建；`doctor`、configure、make、编译探针与 Wine 验证只在 GitHub runner 上运行。

当前仓库包含构建脚本、说明和源码补丁；完整 Wine 二进制已由上述远端成功运行生成并上传。36 项监督器行为测试曾在停止本地编译要求之前通过；此后本地只做 Python AST/帮助输出、Git 补丁、文件校验和与归档内容等不涉及编译的检查，没有重跑包含编译探针的测试，也没有实际 Termux 设备构建或运行结果。

接口依据：

- [Microsoft：IMFPMediaPlayer](https://learn.microsoft.com/en-us/windows/win32/api/mfplay/nn-mfplay-imfpmediaplayer)。
- [Microsoft WinSDK 的 mfplay.h](https://raw.githubusercontent.com/microsoft/win32metadata/main/generation/WinSDK/RecompiledIdlHeaders/um/mfplay.h)。
- [Microsoft：IMFVideoDisplayControl::SetVideoWindow](https://learn.microsoft.com/en-us/windows/win32/api/evr/nf-evr-imfvideodisplaycontrol-setvideowindow)：该方法属于另一接口。
