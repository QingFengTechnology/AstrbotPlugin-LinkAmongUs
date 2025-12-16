from astrbot.api import logger
from astrbot.api.event import AstrMessageEvent
from astrbot.core.platform.sources.aiocqhttp.aiocqhttp_message_event import AiocqhttpMessageEvent

async def set_group_ban(event: AstrMessageEvent, group_id: int | str, user_id: int | str, duration: int) -> str | None:
    """
    群组单人禁言。
    
    Args:
        event: 消息事件对象。
        group_id: 目标群号。
        user_id: 要禁言目标用户的 QQ 号。
        duration: 禁言时长，单位秒，`0` 表示取消禁言。

    Returns:
        操作失败返回的错误信息。操作成功返回`None`。
    """
    try:
        if duration == 0:
            logger.debug(f"[LinkAmongUs] 正在解除成员 {user_id} 在群 {group_id} 的禁言。")
        else:
            logger.debug(f"[LinkAmongUs] 准备在群 {group_id} 禁言成员 {user_id}，时长 {duration} 秒。")
        assert isinstance(event, AiocqhttpMessageEvent)
        await event.bot.set_group_ban(
            group_id=int(group_id),
            user_id=int(user_id),
            duration=duration
        )
        if duration == 0:
            logger.debug(f"[LinkAmongUs] 已解除成员 {user_id} 在群 {group_id} 的禁言。")
        else:
            logger.debug(f"[LinkAmongUs] 已在群 {group_id} 禁言成员 {user_id}。")
        return None
    except Exception as e:
        logger.error(f"[LinkAmongUs] 在群 {group_id} 处理对成员 {user_id} 的禁言操作时发生意外错误: {e}")
        return str(e)

async def get_stranger_info(event: AstrMessageEvent, user_qq_id: int | str, no_cache: bool = True) -> dict | str:
    """
    获取陌生人信息。
    
    Args:
        event: 消息事件对象。
        user_qq_id: 要获取信息的用户 QQ 号。
        no_cache: 是否不使用缓存，默认 `True`。

    Returns:
        包含用户信息的字典，或操作失败返回的错误信息。
    """
    try:
        logger.debug(f"[LinkAmongUs] 正在获取 {user_qq_id} 的账号信息。")
        assert isinstance(event, AiocqhttpMessageEvent)
        stranger_info = await event.bot.get_stranger_info(
            user_id=int(user_qq_id), no_cache=no_cache
        )
        logger.debug(f"[LinkAmongUs] 成功获取 {user_qq_id} 的账号信息。")
        return stranger_info
    except Exception as e:
        logger.error(f"[LinkAmongUs] 获取用户 {user_qq_id} 的信息时发生意外错误: {e}")
        return str(e)

async def set_group_kick(event: AstrMessageEvent, group_id: int | str, user_id: int | str, reject_add_request: bool = False) -> str | None:
    """
    群组踢人。
    
    Args:
        event: 消息事件对象。
        group_id: 目标群号。
        user_id: 要踢人目标用户的 QQ 号。
        reject_add_request: 是否拒绝此人的加群请求，默认 `False`。

    Returns:
        操作失败返回的错误信息。操作成功返回`None`。
    """
    try:
        logger.debug(f"[LinkAmongUs] 正在从群 {group_id} 踢出成员 {user_id}。")
        assert isinstance(event, AiocqhttpMessageEvent)
        await event.bot.set_group_kick(
            group_id=int(group_id),
            user_id=int(user_id),
            reject_add_request=reject_add_request
        )
        logger.debug(f"[LinkAmongUs] 已从群 {group_id} 踢出成员 {user_id}。")
        return None
    except Exception as e:
        logger.error(f"[LinkAmongUs] 在群 {group_id} 踢出成员 {user_id} 时发生意外错误: {e}")
        return str(e)