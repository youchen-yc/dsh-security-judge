# 回归 fixture（规则集 v1.0 / 2026-10-28）

这组文件是**回归保护**用例的固定输入，不是验收标准。

- 规则集基准：`dsh-security-judge` 内置 v1.0（2026-10-28）：
  A–I 共 67 条安全规则 + J 组 5 条交付规则 = 72 条。
- `session-server.json`：完整会话输入快照（会话、代码、事件、通过后编辑事件）。
- `evidence-full.json`：当前规则集在该项目范围内的逐条证据（由 `_generate.mjs` 生成）。
- `architectures-pass.json`：III 级项目达到 8 种及格线的架构集合。
- `architectures-partial.json`：只选 2 种，用于「低于 III 级及格线」用例。
- `architectures-with-conflict.json`：包含 `saltzer` 与 `security-by-obscurity`，用于未登记冲突用例。
- `rule-set-v1.0.json`：规则集版本元数据。

## 规则集变化时

1. 更新 `_generate.mjs` 里的规则集元数据与 fixture 内容；
2. 运行 `node test/fixtures/_generate.mjs` 重新生成；
3. 运行 `node test/regression.mjs`，让差异暴露出来；
4. 按规则变更同步改用例与断言，不要直接放宽。

推荐数与及格线的关系：**推荐数是建议，不是及格线**；及格线只在项目级别已判定时生效
（门禁取下限：I=1、II=3、III=6、IV=10、V=15），级别未判定（unknown）时不阻断。

## 项目级别显式声明

V 级判定依赖「用户规模 + 监管属性」，插件无法从代码推断，因此不靠关键词猜。
在项目根放 `.security-level`，内容为 `I` / `II` / `III` / `IV` / `V`：

- 读取优先级：显式声明 > 自动推断 > unknown；
- 非法值（如 `VI`）直接报错，不静默忽略；
- `security-level-V.txt` / `security-level-VI.txt` 是回归用例的固定输入。
