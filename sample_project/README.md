# 示例多服务项目

这个目录用于演示跨编程语言项目的依赖与漏洞传播分析效果。

示例系统包含：

- `admin-frontend`：后台管理前端
- `customer-portal`：用户门户前端
- `gateway-service`：统一网关服务
- `auth-service`：认证服务
- `order-service`：订单服务
- `analytics-service`：数据分析服务
- `java-service`、`js-frontend`、`python-service`：保留的历史服务模块

`service-map.json` 描述服务之间的调用关系，用于展示漏洞从底层组件向上影响服务的传播路径。
