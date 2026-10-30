# Windows 7 构建

本分支为 `codex/win7`，目标系统为 Windows 7 SP1。CI 生成 32 位
`checker.exe`，可供 Win7 32 位和 64 位系统测试使用。

## 从 GitHub Actions 下载

推送本分支后，会自动运行 **Windows 7** 工作流：

```sh
git push -u origin codex/win7
```

构建成功后，在该次运行页面的 Artifacts 中下载 `checker-win7-x86`。
解压后，使用其中的 `checker.exe` 替换原程序，配合现有的
`checker.cfg.json` 和相关校验文件运行。字体已嵌入程序。

## 固定的构建条件

- Rust 1.77.2，目标为 `i686-pc-windows-msvc`。普通 Windows 目标从
  Rust 1.78 起提高了最低系统要求，因此不能直接升级编译器。
- 使用仓库内的 `Cargo.lock`，通过 `--locked` 构建。
- MSVC v142 / 14.29，Windows SDK 10.0.19041.0。
- vcpkg 固定为 `d5ec528843d29e3a52d745a64b469f810b2cedbf`，与
  `Cargo.toml` 一致。
- `ci/triplets/x86-windows-win7-static.cmake` 将 SDL 等原生库和 C/C++ 运行库
  静态链接，并将原生代码的 Windows API 目标设置为 Win7。

CI 会检查 PE 架构、子系统版本、DLL 依赖，以及 `WaitOnAddress`、
`ProcessPrng` 等已知不兼容的直接或延迟导入。
检查通过只能说明满足这些静态规则；GitHub 的 Windows Server 2022
构建环境不能替代 Win7 实机测试。

原有 `Rust` 工作流仍用于 `master`，下载 Win7 版本时请选上面的专用产物。
