from astrbot.api.star import Context

star_metadata = Context.get_registered_star("astrbot_plugin_link_amongus")
plugin_name = star_metadata.name
version = star_metadata.version
author = star_metadata.author

HELP_MENU = f"""{plugin_name} {version} By {author}
/verify help - 显示此帮助菜单。

/verify create <FriendCode> - 创建一个验证请求。
Args:
  - FriendCode: 必填。你要关联的 Among Us 好友代码。

/verify finish - 完成一个验证请求。
- 由于服务器技术限制暂不支持自动完成，因此您必须要通过此命令主动完成验证请求。

/verify cancel - 取消当前的验证请求。

/verify info - 查询您的绑定信息。
- 显示您当前绑定的 Among Us 角色名、好友代码和绑定时间。

@MessageType.PRIVATE
/verify unban - 解除入群验证禁言。
- 在你完成账号关联后需要通过此命令来解除入群验证的禁言。

@PermissionType.ADMIN
/verify query <QQID|FriendCode> - 查询指定用户的账号关联信息。
Args:
  - QQID|FriendCode: 必填。要查询的用户QQ号或好友代码（二选一）。

@PermissionType.ADMIN
/verify clean - 清理数据库中的非法验证请求。
- 此操作将检查数据库中的验证日志表，将所有创建超过 10 分钟的但仍未结束的验证日志标记为过期。
"""