import asyncio
import aiomysql
import astrbot.api.message_components as Comp
from datetime import datetime

from astrbot.api import logger
from astrbot.api.star import Context
from astrbot.core.message.message_event_result import MessageChain

from .api.databaseManage import database_manage
from .api.callQApi import set_group_kick

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

async def group_verification_timeout_checker(running: bool, db_pool: aiomysql.Pool, polling_interval: int):
    """定时任务：检查并踢出未验证的用户"""
    logger.info("[LinkAmongUs] 已启动未验证成员超时检查。")

    while running:
        try:
            logger.debug("[LinkAmongUs] 正在准备未验证成员超时检查。")
            # 查找需要踢出的成员
            current_time = datetime.now()
            get_result = await database_manage(db_pool, "VerifyGroupLog", "get", status="Banned")
            if not get_result["success"]:
                pass
            elif not get_result["data"]:
                logger.debug("[LinkAmongUs] 未找到验证超时的未验证成员，超时检查结束。")
            else:
                # 查询需要踢出的成员
                all_banned_users = get_result["data"]
                if isinstance(all_banned_users, list):
                    users_to_kick = [user for user in all_banned_users if user.get("KickTime") and user["KickTime"] <= current_time]
                else:
                    user = all_banned_users
                    users_to_kick = [user] if user.get("KickTime") and user["KickTime"] <= current_time else []
                if not users_to_kick:
                    logger.debug("[LinkAmongUs] 没有需要踢出的已超时未验证成员。")
                else:
                    logger.debug(f"[LinkAmongUs] 已找到 {len(users_to_kick)} 个需要踢出的未验证成员。")

                # 踢出成员
                for user in users_to_kick:
                    log_id = user["SQLID"]
                    user_qq_id = user["VerifyUserID"]
                    group_id = user["BanGroupID"]
                    
                    try:
                        await set_group_kick(None, group_id, user_qq_id, False)
                        update_result = await database_manage(db_pool, "VerifyGroupLog", "update", sql_id=log_id, status="Kicked")
                        if update_result["success"]:
                            logger.info(f"[LinkAmongUs] 已在群 {group_id} 踢出用户 {user_qq_id}。")
                        else:
                            logger.error(f"[LinkAmongUs] 更新验证日志失败: {update_result['message']}")
                        
                    except Exception as e:
                        logger.error(f"[LinkAmongUs] 在群 {group_id} 踢出用户 {user_qq_id} 时发生意外错误: {e}")
                                    
                    logger.debug("[LinkAmongUs] 已完成未验证成员超时检查。")
        except Exception as e:
            logger.error(f"[LinkAmongUs] 定时任务执行时发生错误: {e}")

        # 等待
        await asyncio.sleep(polling_interval * 3600)