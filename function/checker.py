import re
from astrbot.api import logger

def friend_code_cheker(friend_code: str, black_list: list) -> bool:
    """校验好友代码
    
    Args:
      friend_code: 要校验的好友代码。

    Returns:
      如果好友代码格式正确，则返回 True；否则返回 False。
    """
    logger.debug("[LinkAmongUs] 正在校验好友代码合法性。")

    # 黑名单检查
    if friend_code in black_list:
        logger.debug(f"[LinkAmongUs] 好友代码命中黑名单，判断为非法。")
        return False

    # 长度校验
    if len(friend_code) < 9 or len(friend_code) > 25:
        logger.debug(f"[LinkAmongUs] 好友代码超出长度限制，判断为非法。")
        return False

    # 基本格式校验
    pattern = r'^[A-Za-z]+#\d{4}$'
    if not re.match(pattern, friend_code):
        logger.debug(f"[LinkAmongUs] 好友代码格式错误，判断为非法。")
        return False

    return True

def qq_id_checker(qq_id: int) -> bool:
    """校验 QQ 号
    
    Args:
      qq_id: 要校验的 QQ 号。

    Returns:
      如果 QQ 号格式正确，则返回 True；否则返回 False。
    """
    logger.debug("[LinkAmongUs] 正在校验 QQ 号合法性。")

    # 基本格式校验
    try:
        int(qq_id)
    except Exception:
        logger.debug("[LinkAmongUs] QQ 号格式不正确，判断为非法。")
        return False

    # 长度校验
    if len(str(qq_id)) < 5 or len(str(qq_id)) > 12:
        logger.debug(f"[LinkAmongUs] QQ 号长度不正确，判断为非法。")
        return False

    return True

async def whitelist_checker(event, private_message: bool, whitelist_groups: list) -> bool:
    """白名单检查
    
    Args:
      event: 消息事件对象
      private_message: 是否允许在私聊中使用
      whitelist_groups: 允许的白名单群组列表

    Returns:
      如果通过白名单检查，返回 True；否则返回 False。
    """
    group_id = event.get_group_id()
    if group_id == "" and not private_message:
        logger.debug("[LinkAmongUs] 不允许在私聊中使用该命令，取消该任务。")
        return False
    if group_id != "" and whitelist_groups and group_id not in whitelist_groups:
        logger.debug(f"[LinkAmongUs] 群 {group_id} 不在白名单内，取消该任务。")
        return False
    return True