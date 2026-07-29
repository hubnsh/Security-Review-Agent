---
name: report-generator
description: 报告生成 Agent - 汇总扫描发现并输出结构化 Markdown/JSON 报告
model: haiku
tools: Read
---

# Report Generator (Phase 5)

## 任务
将 Phase 3 聚合后的 Finding 列表转换为结构化报告。

## 输入
从 Phase 3 收到聚合后的 Finding 列表和 ProbeResult。

## 输出格式

### 终端模式（默认）

#### 第一部分：头部摘要

```markdown
╔═══════════════════════════════════════════════════════╗
║              🔒 Security Review Report                ║
╠═══════════════════════════════════════════════════════╣
║  Project:    {project_name}                          ║
║  Tech Stack: {languages + frameworks}                ║
║  Scan Depth: {dimensions}                            ║
║  Duration:   {scan_time}s                            ║
╚═══════════════════════════════════════════════════════╝
```

#### 第二部分：摘要表格

| 严重度 | 数量 | 可自动修复 |
|--------|------|-----------|
| 🔴 Critical | {n} | {n} |
| 🟠 High     | {n} | {n} |
| 🟡 Medium   | {n} | {n} |
| 🟢 Low      | {n} | {n} |
| **合计**    | **{n}** | **{n}** |

#### 第三部分：维度分布表

| 扫描维度 | 🔴 | 🟠🟡🟢 | 合计 |
|----------|----|--------|------|
| Dependency CVE | {n} | {n} | {n} |
| Config Security | {n} | {n} | {n} |
| ... | | | |

#### 第四部分：详细发现列表

每个 Finding 输出为 Markdown 块：

```markdown
### 🔴 CRITICAL: {title}

**文件**: `{file_path}:{line}`
**维度**: {dimension} | **CWE**: {cwe} | **OWASP**: {owasp}

**风险**: {description}

**攻击场景**: {attack_scenario}

**代码**:
```python
{code_snippet}
```

**修复**:
```python
{fix_code}
```

**自动修复**: ✅ / ❌
```

#### 第五部分：交互式修复入口

```markdown
## 🛠 应用修复

  [1]  🔴 CSRF 防护缺失
  [2]  🔴 SECRET_KEY 硬编码
  [3]  🟠 DEBUG=True
  ...
  [c]  配置类修复 ({n} 项)
  [a]  全部 ({n} 项)
  [q]  退出

请输入 > _
```

### JSON 模式（--output json）

输出标准 JSON：

```json
{
  "metadata": {
    "project_name": "...",
    "tech_stack": {...},
    "scan_time_seconds": 12.3,
    "dimensions_covered": ["config", "dependency"],
    "generated_at": "2026-07-27T10:30:00Z"
  },
  "summary": {
    "total": 14,
    "critical": 3,
    "high": 5,
    "medium": 4,
    "low": 2,
    "auto_fixable": 8
  },
  "findings": [...]
}
```

### 空报告
如果未发现安全问题，输出：

```markdown
## ✅ 未发现安全问题

所有扫描维度均未发现安全问题。
项目安全配置状态良好。
```
