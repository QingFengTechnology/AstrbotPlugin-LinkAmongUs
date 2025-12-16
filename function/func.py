import re
import asyncio
import aiomysql
import astrbot.api.message_components as Comp

from astrbot.api import logger
from astrbot.api.star import Context
from astrbot.core.message.message_event_result import MessageChain
from .api.databaseManage import database_manage

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
    if len(friend_code) < 9 and len(friend_code) > 25:
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

async def verification_timeout_checker(db_pool: aiomysql.Pool, context: Context, user_qq_id: str, target_is_group: bool, timeout: int, umo: str, reminder_time: int):
    """超时检查任务
    
    Args:
        db_pool: 数据库连接池。
        context: 插件接口上下文。
        user_qq_id: 用户 QQ 号。
        timeout: 验证超时时间。
        target_is_group: 发送超时提醒消息的目标是否为群。
        umo: 统一消息源对象，用于发送消息。
        reminder_time: 超时提醒时间，`0` 表示不提醒。
    """
    logger.debug(f"已启动用户 {user_qq_id} 的验证请求超时检查任务。")

    # 检查是否启用超时提醒
    try:
        if reminder_time != 0:
            reminder_time = timeout - reminder_time
            await asyncio.sleep(reminder_time)

            verify_log_result = await database_manage(db_pool, "VerifyLog", "get", latest=True, user_qq_id=user_qq_id)
            verify_log = verify_log_result["data"] if verify_log_result["success"] and verify_log_result["data"] else None
            # 发送超时提醒
            if verify_log and verify_log["Status"] in ["Created", "Retrying"]:
                messageChain_Group = [
                    Comp.At(qq=user_qq_id),
                    Comp.Plain("\u200b\n你的验证请求即将过期，请尽快完成验证！\n如果已使用Among Us完成了验证，请发送/verify finish命令。")
                ]
                messageChain_Private = [
                    Comp.Plain("你的验证请求即将过期，请尽快完成验证！\n如果已使用Among Us完成了验证，请发送/verify finish命令。")
                ]
                if not target_is_group:
                    messageChain = MessageChain(chain=messageChain_Private)
                else:
                    messageChain = MessageChain(chain=messageChain_Group)
                try:
                    await context.send_message(umo, messageChain)
                    logger.debug(f"[LinkAmongUs] 已提醒用户 {user_qq_id} 完成验证请求。")
                except Exception as e:
                    logger.warning(f"[LinkAmongUs] 发送超时提醒消息失败: {e}")
                    logger.warning(f"[LinkAmongUs] 非打断操作，将忽略超时提醒问题，继续执行超时检查。")

                # 等待剩余时间
                await asyncio.sleep(reminder_time)
            else:
                logger.debug(f"用户 {user_qq_id} 已完成验证请求，结束超时检查任务。")
                return
        else:
            await asyncio.sleep(timeout)

        # 最终的超时检查
        verify_log_result = await database_manage(db_pool, "VerifyLog", "get", latest=True, user_qq_id=user_qq_id)
        verify_log = verify_log_result["data"] if verify_log_result["success"] and verify_log_result["data"] else None
        if verify_log and verify_log["Status"] in ["Created", "Retrying"]:
            logger.info(f"[LinkAmongUs] 用户 {user_qq_id} 的验证请求已超时。")
            await database_manage(db_pool, "VerifyLog", "update", sql_id=verify_log["SQLID"], status="Expired")
        else:
            logger.debug(f"用户 {user_qq_id} 已完成验证请求，结束超时检查任务。")
    except Exception as e:
        logger.error(f"[LinkAmongUs] 超时检查任务发生意外错误：{e}")
        try:
            errorMessageChain = [
                Comp.Plain("发生意外错误，请联系管理员。\n插件将尝试直接取消你的验证请求，如未正常工作，请发送 /verify cancel 命令。")
            ]
            await context.send_message(umo, errorMessageChain)
        except Exception as e:
            logger.warning(f"[LinkAmongUs] 发送错误提示失败: {e}")
            logger.warning(f"[LinkAmongUs] 非打断操作，将忽略错误，将继续取消用户 {user_qq_id} 的验证请求。")
        try:
            verify_log_result = await database_manage(db_pool, "VerifyLog", "get", latest=True, user_qq_id=user_qq_id)
            if verify_log_result["success"] and verify_log_result["data"]:
                verify_log = verify_log_result["data"]
                await database_manage(db_pool, "VerifyLog", "update", sql_id=verify_log["SQLID"], status="Cancelled")
            logger.warning(f"[LinkAmongUs] 用户 {user_qq_id} 的验证请求因内部错误被取消。")
        except Exception as e:
            logger.error(f"[LinkAmongUs] 取消用户 {user_qq_id} 的验证请求时发生意外错误：{e}")