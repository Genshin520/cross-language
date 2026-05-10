# 数据库设计说明

本系统面向“跨编程语言项目的依赖与漏洞传播分析工具”的毕业设计目标，数据库不再只保存扫描快照，而是将扫描结果拆分为项目、服务、组件、漏洞、传播路径、风险评估、修复建议、报告和图结构等多个实体，便于后续统计分析、历史对比和论文说明。

## 设计目标

- 支持 Java、JavaScript、Python 等多语言项目的依赖组件持久化。
- 支持服务调用关系、组件依赖关系和漏洞传播路径的结构化存储。
- 支持每次扫描的历史追踪、风险对比、报告下载和可视化数据复用。
- 保留 `scan_records.result_payload` 作为完整快照，保证前端兼容和结果回放。
- 同步写入明细表，使数据库设计具有较完整的工程复杂度。

## 业务表

| 表名 | 作用 |
| --- | --- |
| `projects` | 项目基础信息，包括项目路径、首次扫描时间、最近扫描时间和扫描次数。 |
| `scan_records` | 扫描主表，记录每次扫描的总体指标、报告文件和完整 JSON 快照。 |
| `services` | 服务模块表，记录每次扫描中的服务名称、组件数量、漏洞数量和语言集合。 |
| `components` | 依赖组件表，记录组件名称、版本、语言、所属服务、依赖类型和来源文件。 |
| `service_relations` | 服务调用关系表，记录服务之间的调用边。 |
| `vulnerabilities` | 漏洞知识库表，记录 CVE、影响组件、严重程度、修复版本等信息。 |
| `scan_vulnerabilities` | 扫描漏洞命中表，记录某次扫描中组件命中的漏洞和传播评分。 |
| `propagation_paths` | 漏洞传播路径表，记录完整路径和最短路径，支持传播过程追踪。 |
| `risk_assessments` | 风险评估表，记录风险等级、风险得分、传播得分和评估原因。 |
| `remediation_suggestions` | 修复建议表，记录目标版本、修复优先级、影响服务和建议内容。 |
| `reports` | 报告文件表，记录 JSON、TXT、HTML 等报告文件。 |
| `graph_nodes` | 图节点表，保存服务节点和组件节点，用于关系图复现。 |
| `graph_edges` | 图边表，保存服务调用边和组件依赖边。 |
| `scan_statistics` | 统计指标表，保存语言分布、服务分布、风险分布等可视化指标。 |
| `analysis_methods` | 分析方法表，记录每个漏洞组件使用的传播分析方法。 |
| `architecture_profiles` | 项目架构识别表，记录系统识别出的项目类型、前端模块、后端模块和识别依据。 |
| `module_impacts` | 模块影响分析表，记录漏洞组件对上游模块、直接调用方、下游模块和可读传播链路的影响。 |

## 核心关系

- 一个 `project` 可以对应多次 `scan_records`。
- 一次 `scan_record` 可以对应多个 `services`、`components`、`service_relations`、`risk_assessments` 和 `reports`。
- `components.component_uid` 与 `scan_vulnerabilities.component_uid`、`risk_assessments.component_uid`、`propagation_paths.component_uid`、`remediation_suggestions.component_uid` 关联。
- `vulnerabilities.cve_id` 与 `scan_vulnerabilities.cve_id` 关联，用于区分漏洞知识库和某次扫描命中结果。
- `graph_nodes` 和 `graph_edges` 保存图结构，服务于传播路径可视化。
- `architecture_profiles` 与 `module_impacts` 进一步保存面向用户的中文分析结果，使系统不仅展示配置文件级别的数据，也能解释模块之间的业务影响。

## 与论文工作的对应

- 依赖解析模块：对应 `services`、`components`、`service_relations`。
- 漏洞识别模块：对应 `vulnerabilities`、`scan_vulnerabilities`。
- 传播路径分析模块：对应 `propagation_paths`、`graph_nodes`、`graph_edges`、`analysis_methods`。
- 项目架构识别模块：对应 `architecture_profiles`，用于说明项目属于 Java 后端、前后端分离或多语言微服务等类型。
- 模块影响展示模块：对应 `module_impacts`，用于说明漏洞组件影响的上游模块、直接调用方和下游依赖模块。
- 风险评估模块：对应 `risk_assessments`、`scan_statistics`。
- 修复建议模块：对应 `remediation_suggestions`。
- 报告与历史模块：对应 `scan_records`、`reports`、`projects`。

该设计使系统不仅具备前端展示和算法分析功能，也具备较完整的数据建模与结果追踪能力，更符合毕业设计对工程复杂度和工作量的要求。
