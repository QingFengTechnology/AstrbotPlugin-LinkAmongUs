# LinkAmongUs 插件

一个用于通过验证将 Among Us 账户与 QQ 账户关联的 Astrbot 插件。

## 功能特性

- 通过 API 验证将 Among Us 账户与 QQ 账户关联
- 支持创建和检查验证请求
- 数据库存储验证信息
- 黑白名单管理
- 超时处理机制

## 安装方法

1. 将插件文件夹复制到 Astrbot 的 plugins 目录下
2. 在 Astrbot 配置文件中添加插件配置
3. 安装依赖：`pip install -r requirements.txt`
4. 重启 Astrbot

## 配置说明

在 Astrbot 的配置文件中添加以下配置项：

```yaml
LinkAmongUs:
  # API 配置
  APIConfig:
    APIConfig_Key: "your_api_key"  # API 密钥
    APIConfig_EndPoint: "http://your-api-endpoint.com"  # API 端点
    APIConfig_ServerName: "YourServerName"  # 服务器名称
  
  # 验证配置
  VerifyConfig:
    # 创建验证配置
    VerifyConfig_CreateVerfiyConfig:
      CreateVerfiyConfig_ProcessDuration: 600  # 验证处理时长（秒）
      CreateVerfiyConfig_ApiTimeout: 6  # API 请求超时时间（秒）
    
    # 黑名单好友代码
    VerifyConfig_BlackFriendCode:
      - "12345678"
      - "87654321"
    
    # 白名单群组（留空则在所有群组中启用）
    VerifyConfig_WhiteGroup: []
```

## 使用方法

### 创建验证请求

```
/verify create <好友代码>
```

### 检查验证状态

```
/verify check
```

## 数据库结构

插件使用两个主要的数据表：

1. `VerifyLog` - 存储验证请求日志
2. `VerifyUserData` - 存储已验证的用户数据

## API 接口

插件与以下 API 接口交互：

- `PUT /api/verify` - 创建验证请求
- `GET /api/verify` - 查询验证状态
- `DELETE /api/verify` - 删除验证请求

## 测试

插件包含完整的单元测试，可以通过以下方式运行：

```bash
python test_plugin.py
```

## 技术支持

如有问题，请联系开发者或提交 Issue。