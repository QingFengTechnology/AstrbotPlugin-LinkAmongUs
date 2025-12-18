from typing import TYPE_CHECKING

import astrbot.api.message_components as Comp
from astrbot.api.star import Context

if TYPE_CHECKING:
    from ..main import LinkAmongUs

def help_menu(self: 'LinkAmongUs', context: Context) -> list[Comp.BaseMessageComponent]:
    """获取帮助菜单的消息模板

    Args:
      self: 插件实例。
      context: 插件接口上下文。
    
    Returns:
      包含帮助菜单的消息链。
    """
    metadata = context.get_registered_star(self.name)
    chain = [
        Comp.Plain(f"{metadata.name} {metadata.version} By {metadata.author}\n"),
        Comp.Plain("帮助菜单\n\n\u200b"),
        Comp.Plain("/verify help - 显示此帮助菜单。\n\u200b"),
        Comp.Plain("/verify create <FriendCode> - 创建一个验证请求。\n\u200b"),
        Comp.Plain("Args:\n\u200b"),
        Comp.Plain("- FriendCode: 必填。你要关联的 Among Us 好友代码。\n\u200b"),
        Comp.Plain("/verify finish - 完成一个验证请求。\n\u200b"),
        Comp.Plain("/verify cancel - 取消当前的验证请求。\n\u200b"),
        Comp.Plain("/verify info - 查询你当前绑定的账号信息。\n\u200b"),
        Comp.Plain("[仅超管可用]/verify query <QQID|FriendCode> - 查询指定用户的账号关联信息。\n\u200b"),
        Comp.Plain("Args:\n\u200b"),
        Comp.Plain("- QQID|FriendCode: 必填。要查询的用户QQ号或好友代码（二选一）。"),
    ]
    return chain