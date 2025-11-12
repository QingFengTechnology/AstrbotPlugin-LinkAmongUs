# Login with Among Us

![AstrbotPlugin-LinkAmongUs](https://socialify.git.ci/QingFengTechnology/AstrbotPlugin-LinkAmongUs/image?description=1&font=KoHo&language=1&name=1&pattern=Solid&theme=Auto)

## 功能

- 通过 API 验证将 Among Us 账户与 QQ 账户关联
- 支持创建和检查验证请求
- 数据库存储验证信息
- 黑白名单管理
- 超时处理机制

## 安装

在 Astrbot WebUI 插件页面点击`安装`按钮，选择`从链接安装`，复制粘贴本仓库 URL 并点击安装即可。

> [!important]
> 此插件仅适用于 aiocqhttp 平台，其余平台发来的请求插件将不会响应。

## 使用

> [!Note]
> 插件安装后需要进行配置，否则无法正常工作。

### 帮助菜单

```
/verify help
```
显示帮助菜单。

### 创建验证

```
/verify create <FriendCode>
```
创建一个验证请求，其中`<FriendCode>`用于验证账户的好友代码，该参数必填。

### 完成验证

```
/verify finish
```
完成验证请求。\
由于 Nmpostor 不支持回调，因此需要通过该命令主动让插件请求 API 校验验证请求。

### 清理验证

```
/verify clean
```
清理数据表`VerifyLog`中已超时但状态仍处于已创建/重试中的验证请求。

### 查询用户

```
/verify info
```
查询自己关联的 Among Us 账号信息。

```
/verify query <QQID|FriendCode>
```
查询指定用户的账号关联信息。\
其中`<QQID|FriendCode>`为用户 QQ 号或 Among Us 好友代码，该参数必填。