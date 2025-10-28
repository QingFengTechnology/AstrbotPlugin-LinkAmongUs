# Todo

相对于 Readme，本文档主要提供了开发细则，告诉您我们预期中的插件应为什么样，您应当根据此文档开发完整插件。

> [!Important]
> 关于 Nmpostor 验证 API 文档，请[点击此处查看](https://github.com/NikoCat233/AU-Verify-Docs)，在下文中我们将**默认您已阅读**此文档。

> [!Important]
> 本插件主要使用 MySQL (8.x，开发者所用版本为8.4)来存储用户数据，关于用到的数据表，请查看[VerifyLog](VerifyLog.sql)与[VerifyUserData](VerifyUserData.sql)，在本文档中我们将**默认您查阅过**此数据表。

## 命令

### 创建验证

```
/verify create <FriendCode>
# 创建一个验证请求，参数`FriendCode`为玩家的好友代码，该参数必填。
```

触发命令后，插件首先进行一个简单的校验，检查用户输入的参数`FriendCode`是否完全匹配上了插件配置`VerifyConfig_BlackFriendCode`中的任意一项。\
其次插件将在数据表 VerifyUserData 中检查用户的 QQ 号是否已存于数据库中，再检查用户填写的参数`FriendCode`的值是否已存在于数据库中，如果上述验证结果任意一个为已存在应当取消执行后续流程，并且相应的发送消息提示用户失败原因。
> 提示用户好友代码被拉黑的参考消息：
> ```text
> 创建验证请求失败，此好友代码不能用于创建验证请求。
> ```

> 提示用户 QQ 号已绑定账号的参考消息：
> ```text
> 创建验证请求失败，你的账号已绑定 {VerifyUserData.UserFriendCode}。
> 若要更换，请联系管理员。
> ```
> `{VerifyUserData.UserFriendCode}`为数据库中查询该用户 QQ 号得到的相关联的好友代码。

> 提示用户填写的好友代码已被绑定的参考消息：
> ```text
> 创建验证请求失败，该好友代码已绑定 {VerifyUserData.UserQQID}。
> 若要更换，请联系管理员。
> ```
> `{VerifyUserData.UserQQID}`为数据库中查询用户填写的参数`FriendCode`得到的相关联的 QQ 号。

如果在数据库中没有查询到结果(即该用户的 QQ 与要绑定的好友代码均没有被绑定)将进入创建验证流程，插件将向 API 发送 PUT 请求，(根据 API 文档)请求体如下：
```json
{
    "ApiKey": "{APIConfig_Key}",
    "FriendCode": "{FriendCode}"
}
```
- `{APIConfig_Key}` - 插件配置中的 API Key。
- `{FriendCode}` - 用户在创建请求时填写的参数`FriendCode`。

随后插件将等待 API 返回响应，若请求失败或收到的响应结果格式与预期不符应当取消执行后续流程，并且相应的发送消息提示用户错误原因。
> 提示用户请求失败的参考消息：
> ```text
> 创建验证请求失败，请求 API 时出现异常，请联系管理员。
> ```

> 预期不符的结果*例如*请求超时、API 响应结果不是 Json 格式、API 响应结果不包含文档中提到的**全部**参数(即`VerifyStatus`、`VerifyCode`、`FriendCode`、`ExpiresAt`)。

收到响应结果后插件将向数据表 VerifyLog 写入数据，参考传入值：
- `SQLID` - **不需要**传入，该字段为 AUTO_INCREMENT。
- `CreateTime` - **不需要**传入，该字段为 DEFAULT_GENERATED。
- `Status` - 应为 **Created**，表示该验证请求刚刚创建。
- `UserQQID` - 应为**发起验证的用户的 QQ 号**。
- `UserFriendCode` - 应为**用户在创建请求时填写的参数`FriendCode`**。
- `VerifyCode` - 应为 **API 返回结果中的`VerifyCode`**。

写入数据库完成后就代表该请求已经正式创建了，此时应当向用户发送消息，并附带上`VerifyCode`以及其他信息以指示用户完成验证。
> 提示用户请求创建的参考消息：
> ```text
> 成功创建验证请求，请在 {CreateVerfiyConfig_ProcessDuration} 秒内使用账号 {FriendCode} 加入 {APIConfig_ServerName} 房间 {VerifyCode} 以完成验证。
> ```
> - `{CreateVerfiyConfig_ProcessDuration}` - 插件配置中的验证超时时间。
> - `{FriendCode}` - 插件在创建验证中写入数据库时传入的 FriendCode。
> - `{APIConfig_ServerName}` - 插件配置中的服务器名称。
> - `{VerifyCode}` - 插件在创建验证中写入数据库时传入的 VerifyCode。

随后插件应以秒为单位计时配置中的验证超时时间，倒计时结束后应重新读取一遍刚刚向数据表 VerifyLog 写入的数据，检查其 Status 是否为 Verified / Cancelled / Expired，如果不是则将 Status 更新为 Expired。

### 完成验证

```
/verify check
# 完成验证请求，仅先前创建过验证请求且未完成的用户可用。
```

触发命令后，插件将在数据表 VerifyLog 中检查用户的 QQ 号是否存在(即是否创建过验证请求)，如果没有则应当取消执行后续流程，并且相应的发送消息提示用户。

> 提示用户没有创建验证请求的参考消息：
> ```text
> 你还没有创建验证请求，或是该验证请求已过期。
> ```

如果查询到了有创建过验证请求，则检查这条数据的 Status 是否为`Created`/`Retrying`，如果是则应当进入验证流程。\
但如果不是，则应当取消执行后续流程，并且相应的发送消息提示用户。
> 提示用户验证状态无效的参考消息：
> ```text
> 你的验证请求已失效，请重新创建验证请求。
> ```

> [!NOTE]
> 用户可以创建多次验证请求，因此在开发时需要根据 CreateTime(推荐,根据创建时间判断) / SQLID(根据 ID 大小判断) 判断是否为最近一次创建的请求。\
> 只应当基于最近一次的验证请求进行处理。

进入验证流程后，插件将向 API 发送 GET 请求，(根据 API 文档)要访问的 URL 应该如下：
```
{APIConfig_EndPoint}/api/verify?api_key={APIConfig_Key}&verify_code={VerifyLog.VerifyCode}
```
- `{APIConfig_EndPoint}` - 插件配置中的 API 端点。
- `{APIConfig_Key}` - 插件配置中的 API Key。
- `{VerifyLog.VerifyCode}` - 数据表 VerifyLog 中对应玩家的数据中的 VerifyCode。

随后插件将等待 API 返回响应，由于此类型的 API 响应结果不一，因此需要根据情况处理：

---

如果 API 返回 NotVerified，则应更新数据表 VerifyLog 对应用户的数据，将 Status 更新为 Retrying，随后发送以下消息提示用户：
```text
验证失败，你还没有进行验证。
```

---

如果 API 返回 HttpPending，则应更新数据表 VerifyLog 对应用户的数据，将 Status 更新为 Retrying，随后发送以下消息提示用户：
```text
验证失败，请等待服务端处理完成。
请稍后重试提交验证。
```

---

如果 API 返回 Verified，则应当向数据表 VerifyUserData 写入数据，参考传入值：
- `SQLID` - **不需要**传入，该字段为 AUTO_INCREMENT。
- `LastUpdated` - **不需要**传入，该字段为 DEFAULT_GENERATED。
- `UserQQName` - 应为**发起验证的用户的 QQ 名称**。
- `UserQQID` - 应为**发起验证的用户的 QQ 号**。
- `UserAmongUsName` - 应为 **API 返回结果中的`PlayerName`**。
- `UserFriendCode` - 应为 **API 返回结果中的`FriendCode`**。
- `UserPuid` - 应为 **API 返回结果中的`Puid`**。
- `UserHashedPuid` - 应为 **API 返回结果中的`HashedPuid`**。
- `UserUdpPlatform` - 应为 **API 返回结果中的`UdpPlatform`**。
- `UserTokenPlatform` - 应为 **API 返回结果中的`TokenPlatform`**。
- `UserUdpIP` - 应为 **API 返回结果中的`UdpIp`**。
- `UserHttpIp` - 应为 **API 返回结果中的`HttpIp`**。

随后插件将向 API 发送 DELETE 请求，(根据 API 文档)请求体如下：
```json
{
    "apikey": "{APIConfig_KEY}",
    "verifycode": "{VerifyLog.VerifyCode}"
}
```
- `{APIConfig_Key}` - 插件配置中的 API Key。
- `{VerifyLog.VerifyCode}` - 数据表 VerifyLog 中对应玩家的数据中的 VerifyCode。

完成后，插件将更新数据表 VerifyLog 对应用户的数据，将其 Status 更新为 Verified，随后发送以下消息提示用户：
```text
验证成功！已将 {VerifyUserData.UserAmongUsName}({VerifyUserData.UserFriendCode}) 关联 QQ {VerifyUserData.UserQQID}。
```
- `{VerifyUserData.UserFriendCode}` - 数据表 VerifyUserData 中对应玩家数据中的 UserAmongUsName。
- `{VerifyUserData.UserAmongUsName}` - 数据表 VerifyUserData 中对应玩家数据中的 UserQQID。
- `{VerifyUserData.UserQQID}` - 数据表 VerifyUserData 中对应玩家数据中的 UserQQID。

---

如果 API 返回 Expired，则应更新数据表 VerifyLog 对应用户的数据，将 Status 更新为 Expired，随后发送以下消息提示用户：
```text
验证失败，请求已过期，请重新创建验证请求。
```

---