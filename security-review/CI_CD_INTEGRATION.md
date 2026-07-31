# CI/CD Integration: Security Review with GitHub Actions

以下示例将 Security Review Agent 集成到 GitHub Actions 中，每次 PR 或 push 自动运行安全扫描。

## 用法

将 `.github/workflows/security-review.yml` 添加到你的项目中。

### 纯 CLI 模式（推荐：无需 Claude Code）

使用 `engine.py` 独立运行，不依赖 Claude Code，适合大多数 CI 场景。
stdout 只输出 JSON（进度消息走 stderr），可直接管道解析：

```yaml
# .github/workflows/security-review.yml
name: Security Review

on:
  pull_request:
    branches: [main, master, develop]
  push:
    branches: [main, master]

jobs:
  security-review:
    runs-on: ubuntu-latest
    permissions:
      contents: read

    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # 完整 git 历史，支持 --diff 模式

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install Security Review Agent
        run: |
          # 从你的仓库复制 security-review/ 目录，或通过 pip/git 安装
          # 这里假设已克隆到 ./security-review
          pip install PyYAML pip-audit -q

      - name: Run Security Scan
        id: scan
        run: |
          python security-review/engine.py \
            --path . \
            --output json \
            --no-fix \
            --diff origin/${{ github.base_ref || 'main' }} \
            > security-report.json
          # 生成 Markdown 报告供归档
          python security-review/engine.py \
            --path . --output markdown --no-fix \
            --diff origin/${{ github.base_ref || 'main' }} \
            > security-report.md 2>/dev/null || true

      - name: Fail on Critical/High
        if: always()
        run: |
          python - <<'EOF'
          import json
          with open('security-report.json', encoding='utf-8') as f:
              report = json.load(f)
          s = report['summary']
          print(f"Critical={s['critical']} High={s['high']} Medium={s['medium']} Low={s['low']} Total={s['total']}")
          if s['critical'] > 0 or s['high'] > 0:
              raise SystemExit(1)
          EOF

      - name: Upload Report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-review-report
          path: |
            security-report.json
            security-report.md
```

### CI 模式（Claude Code：每次 PR 自动扫描）

```yaml
# .github/workflows/security-review.yml
name: Security Review

on:
  pull_request:
    branches: [main, master, develop]
  push:
    branches: [main, master]

jobs:
  security-review:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write  # 用于 PR 评论

    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # 完整 git 历史，支持 --diff 模式

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install pip-audit (optional)
        run: pip install pip-audit -q

      - name: Run Security Review
        uses: anthropic/claude-code-action@v1
        with:
          command: /security-review --output json --no-fix

      - name: Upload Report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-review-report
          path: security-review-report.json
```

### PR 评论模式

```yaml
# .github/workflows/security-review-pr.yml
name: Security Review - PR Comment

on:
  pull_request:
    types: [opened, synchronize]

jobs:
  security-review:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write

    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: |
          pip install pip-audit bandit -q 2>/dev/null || true

      - name: Run Security Review
        id: review
        run: |
          claude /security-review --output json --no-fix --diff origin/${{ github.base_ref }} > report.json

      - name: Comment PR
        if: always()
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const report = JSON.parse(fs.readFileSync('report.json', 'utf8'));
            const { summary } = report;

            let body = `## 🔒 Security Review\n\n`;
            body += `| Severity | Count |\n|---------|------|\n`;
            body += `| 🔴 Critical | ${summary.critical} |\n`;
            body += `| 🟠 High | ${summary.high} |\n`;
            body += `| 🟡 Medium | ${summary.medium} |\n`;
            body += `| 🟢 Low | ${summary.low} |\n`;
            body += `| **Total** | **${summary.total}** |\n\n`;

            if (summary.critical > 0 || summary.high > 0) {
              body += `> ⚠️ Found ${summary.critical + summary.high} high-severity issues.\n`;
            }

            if (summary.total === 0) {
              body += '✅ No security issues found.';
            }

            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: body
            });
```

## 自定义选项

### GitLab CI

```yaml
# .gitlab-ci.yml
security-review:
  stage: test
  image: python:3.11
  before_script:
    - pip install pip-audit bandit -q
  script:
    - claude /security-review --output json --no-fix --diff origin/$CI_MERGE_REQUEST_TARGET_BRANCH_NAME
  artifacts:
    paths:
      - security-review-report.json
    when: always
  only:
    - merge_requests
```

### 本地运行（pre-commit hook）

```bash
# .git/hooks/pre-commit
#!/bin/bash
echo "🔒 Running Security Review..."
claude /security-review --quick --output json --no-fix
```

## 输出说明

| 模式 | 输出 | 用途 |
|------|------|------|
| `--output json --no-fix` | `security-review-report.json` | CI 分析 + 存档 |
| `--output markdown --no-fix` | `security-review-report.md` | 人类可读报告文件 |
| `--output terminal` | 终端 Markdown 表格 | 开发时阅读 |
| `--apply all` | 自动应用全部可修复项 | 批量修复（需人工 review diff） |
| `--apply 1,3,5` | 按报告编号应用修复 | 选择性修复 |
| `--diff origin/main` | 仅扫描变更文件 | PR 增量扫描 |

> **说明**：json/markdown 模式下进度消息输出到 stderr，stdout 只有报告本体，可直接重定向到文件或管道解析。

## GitHub Action 输出 Schema

```json
{
  "metadata": {
    "project_name": "my-project",
    "tech_stack": {"languages": ["python"], "frameworks": ["django"]},
    "scan_time_seconds": 8.5,
    "dimensions_covered": ["config", "dependency", "sast", "auth", "business"],
    "generated_at": "2026-07-28T10:30:00Z"
  },
  "summary": {
    "total": 8,
    "critical": 2,
    "high": 3,
    "medium": 2,
    "low": 1,
    "auto_fixable": 5
  },
  "findings": [
    {
      "id": "django-csrf-disabled",
      "severity": "critical",
      "title": "CSRF Middleware Disabled",
      "file_path": "backend/settings.py",
      "line": 33,
      "auto_fixable": true
    }
  ]
}
```
