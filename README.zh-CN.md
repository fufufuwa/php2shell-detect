# php2shell-detect（中文说明）

**PHP2Shell（CVE-2026-109618 / CVE-2026-109619）非破坏性检测工具与版本差分 oracle**
（PHP core 状态损坏漏洞，2026-10-21 披露，修复于 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35）。

核心贡献是一个 **stale-PS(id) 泄露 oracle**——用干净的带外信号区分漏洞版与修复版，
在完全相同的配置下实测：**PHP 8.5.11（漏洞版）4/4 命中 vs PHP 8.5.12（修复版）0/4**。

完整实测矩阵见 [docs/DIFFERENTIAL-RESULTS.md](docs/DIFFERENTIAL-RESULTS.md)（英文）。

## 快速开始（本地实验台）

```sh
cd lab
docker compose up -d           # 4 个 loopback 容器：8.5.11/8.5.12 + 8.4.26/8.4.27
python leak_differential.py    # 头条实验：预期 4/4 vs 0/4
```

## 扫描器分层（php2shell.py，纯标准库，Python 3.8+）

| 层 | 信号 | 判定力 |
|---|---|---|
| T0 | `X-Powered-By` 落在受影响版本矩阵 | 必要条件（可被隐藏） |
| T1 | 非法 sid 带内警告；P1 无 cookie sid 注入 | 攻击面活跃——**修复版同样触发，绝不能单独定罪** |
| **T2** | **stale-PS(id) 泄露 oracle（arm + read）** | **真正的版本差分；无需版本头即可判定 VULNERABLE** |
| T2b | OOM alloc 指纹（filename 阶梯） | 仅佐证——(构建, memory_limit, fnlen) 联合函数 |
| T3 | kill receipt（`--destructive` 显式开启） | 破坏性层级，仅限明确授权的深度验证 |

输出：`.report.md`（人读）、`.verdict.json`（机器判定）、`.transcript.jsonl`（完整
请求/响应记录）。`--json` 输出到 stdout 供流水线集成；`--batch` 批量扫描。

## 诚实的限制

1. **T2 回收 shape 是 per-build 的**：841×43B 布局在 PHP 8.5.11 上 4/4 验证；
   其他构建需要各自的 shape 矩阵——未泄露 ≠ 不受影响。
2. **T1 信号在修复版上同样触发**——只证明 rfc1867 预初始化会话路径可达。
3. oracle 需要**单 worker 粘性**（arm 和 read 必须落在同一 worker）；
   多 worker 生产环境概率命中，`--leak-tries`（默认 3）重试。
4. **不含武器化**：fire 阶段（伪造 HashTable → 任意调用）需要 per-build 偏移，
   不属于检测工具范畴。公开 ASAN 定罪已证明根因。
5. var_destroy `__destruct` 重入 UAF 在 **8.4.27 上依旧存活**，可能是独立新 bug，
   已标记供后续研究。

## 致谢

- [unlimit0118/CVE-2026-109619-php2shell-poc](https://github.com/unlimit0118/CVE-2026-109619-php2shell-poc) —
  arm/read 泄露 shape 的首次公开演示（本仓库 oracle 建立在该披露之上）
- [WoYinDao/CVE-2026-109618-CVSS-9.2-Critical](https://github.com/WoYinDao/CVE-2026-109618-CVSS-9.2-Critical) —
  P1–P5 原语、补丁 diff 分析、ASAN 定罪、18 发负矩阵
- [pentestershell/php2shellbt](https://github.com/pentestershell/php2shellbt) —
  扫描器先例（本仓库明确修正其在修复版上的误报行为）

## 许可与授权使用

MIT（见 [LICENSE](LICENSE)）；致谢见 [NOTICE](NOTICE)）。

本仓库只包含**检测工具与本地实验台**，针对已公开、已修复的 CVE；不含武器化偏移、
不含目标清单。扫描器仅可用于已明确授权测试的系统。实验台只绑定 127.0.0.1。
