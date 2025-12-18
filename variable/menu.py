import astrbot.api.message_components as Comp
from astrbot.core.star import StarMetadata

def help_menu(metadata: StarMetadata) -> list[Comp.BaseMessageComponent]:
    """获取帮助菜单的消息模板

    Args:
      metadata: 插件元数据信息。
    
    Returns:
      包含帮助菜单的消息链。
    """
    chain = [
        Comp.Plain(f"LinkAmongUs {metadata.version} By QingFeng\n"),
        Comp.Plain("===[帮助菜单]===\n\n\u200b"),
        Comp.Plain("/verify help - 显示此帮助菜单。\n\u200b"),
        Comp.Plain("/verify create <FriendCode> - 创建一个验证请求。\n\u200b"),
        Comp.Plain("Args:\n\u200b"),
        Comp.Plain("- <FriendCode>: 必填。你要关联的 Among Us 好友代码。\n\u200b"),
        Comp.Plain("/verify finish - 完成一个验证请求。\n\u200b"),
        Comp.Plain("/verify cancel - 取消当前的验证请求。\n\u200b"),
        Comp.Plain("/verify info - 查询你当前绑定的账号信息。\n\u200b"),
        Comp.Plain("[仅超管可用]/verify query <QQID|FriendCode> - 查询指定用户的账号关联信息。\n\u200b"),
        Comp.Plain("Args:\n\u200b"),
        Comp.Plain("- <QQID|FriendCode>: 必填。要查询的用户QQ号或好友代码（二选一）。"),
    ]
    return chain