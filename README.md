# Astrbot 账号关联插件

![AstrbotPlugin-LinkAmongUs](Asset/header-dark.svg)

## 安装

在 Astrbot 应用市场点击右下角 + 号，选择`从链接安装`，复制粘贴本仓库 URL 并点击安装即可。

## 使用

```
/verify create <FriendCode>
```

创建一个验证请求，其中`FriendCode`为玩家的好友代码。

```
/verify check
```

主动请求完成验证，只有在先前创建过验证请求的玩家才可以使用此命令。

```
/verify cancel [QQID|FriendCode]
```

取消当前验证请求，若出现意外情况无法完成验证，可以通过该命令立即回收占用的资源。\
默认(不填写参数)取消自己的验证请求，若为管理员还可通过提供 QQ 号或好友代码来取消其他人的验证请求。

```
/verify status <QQID|FriendCode>
```

查询特定用户的验证状态，需要提供 QQ 号或好友代码。

```
/verify query <QQID|FriendCode>
```

查询特定用户的身份信息，需要提供 QQ 号或好友代码。\
此选项主要用于检查某个用户是否完成验证，而不是获取该玩家的完整信息，因此出于隐私保护，大部分收集到的数据不会被发送出来。