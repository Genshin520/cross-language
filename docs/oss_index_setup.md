# OSS Index 配置说明

系统已接入 Sonatype Guide Compatibility API 中的 OSS Index v3 组件漏洞查询接口。由于接口需要认证访问，请在启动 Flask 前配置以下环境变量：

```powershell
$env:OSS_INDEX_USERNAME="你的 OSS Index / Sonatype 账号邮箱"
$env:OSS_INDEX_TOKEN="你的 API Token"
```

如果需要切回旧 OSS Index 域名，也可以额外配置：

```powershell
$env:OSS_INDEX_API_URL="https://ossindex.sonatype.org/api/v3/component-report"
```

配置完成后重新启动项目：

```powershell
.venv\Scripts\python.exe -m flask --app backend.app run --host 127.0.0.1 --port 5000
```

同步逻辑会优先使用最近一次扫描结果中的组件名称、版本和语言生成 Package URL，例如：

```text
pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1
pkg:npm/lodash@4.17.20
pkg:pypi/requests@2.19.1
```
