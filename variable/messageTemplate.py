import astrbot.api.message_components as Comp
from astrbot.api.star import Context

def help_menu(self, context: Context) -> str:
    """获取帮助菜单的消息模板

    Args:
      self: 插件实例。
      context: 插件接口上下文。
    """
    metadata = context.get_registered_star(self.name)
    return f"""{metadata.name} {metadata.version} By {metadata.author}

帮助菜单：

/verify help - 显示此帮助菜单。

/verify create <FriendCode> - 创建一个验证请求。
Args:
  - FriendCode: 必填。你要关联的 Among Us 好友代码。

/verify finish - 完成一个验证请求。
- 由于服务器技术限制暂不支持自动完成，因此您必须要通过此命令主动完成验证请求。

/verify cancel - 取消当前的验证请求。

/verify info - 查询您的绑定信息。
- 显示您当前绑定的 Among Us 角色名、好友代码和绑定时间。

@PermissionType.ADMIN
/verify query <QQID|FriendCode> - 查询指定用户的账号关联信息。
Args:
  - QQID|FriendCode: 必填。要查询的用户QQ号或好友代码（二选一）。
"""

def new_user_join(user_qq_id: int | str):
    """获取入群验证提示的消息模板"""
    return [
Comp.At(qq=user_qq_id),
Comp.Plain("""\u200b\n本群已启用清风服关联账号验证服务，您需要与机器人私聊完成关联验证。
与机器人私聊发送 /verify help 命令以获取帮助。
在完成验证之前，您将不得发言，若长时间未完成验证，您将被移出本群。""")
]