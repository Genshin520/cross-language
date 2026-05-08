# 跨编程语言项目依赖与漏洞传播分析平台

这是一个面向毕业设计的原型项目，用于分析多语言软件系统中的依赖关系、漏洞命中情况以及漏洞影响范围。

## 当前完成情况

- Flask 后端原型
- Java / JavaScript / Python 依赖解析
- 统一依赖图构建
- 本地漏洞库匹配
- BFS 漏洞影响分析
- 风险等级评估
- SQLite 历史扫描记录
- D3.js 前端可视化页面
- JSON / TXT / HTML 报告导出

## 目录结构

```text
backend/
  app/
    static/
    templates/
  data/
sample_project/
reports/
requirements.txt
README.md
```

## 在 VS Code 中启动

1. 用 VS Code 打开项目目录：`C:\Users\20481\Documents\New project 2`
2. 打开内置终端，执行 `python -m venv .venv`
3. 激活环境：`.venv\Scripts\Activate.ps1`
4. 安装依赖：`pip install -r requirements.txt`
5. 打开“运行和调试”，选择 `Run Flask Prototype`
6. 启动后访问：`http://127.0.0.1:5000`

项目已经附带：

- `.vscode/settings.json`
- `.vscode/launch.json`
- `.vscode/tasks.json`
- `.vscode/extensions.json`

如果你更喜欢任务方式，也可以在 VS Code 中直接运行：

- `Create venv`
- `Install requirements`
- `Run project`

## 演示方式

- 点击“加载示例项目”直接查看内置跨语言样例
- 或输入你自己的项目目录进行扫描

## 下一阶段建议

- 接入真实漏洞源或同步本地漏洞库
- 增强 Maven 传递依赖解析
- 增加服务之间调用拓扑
- 切换 SQLite 到 MySQL
- 增加论文所需用例、对比实验和截图
