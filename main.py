import asyncio
import aiohttp
import aiomysql
from typing import Optional, Dict, Any
from datetime import datetime

import astrbot.api.message_components as Comp
from astrbot.api.event import filter, AstrMessageEvent
from astrbot.api.star import Context, Star
from astrbot.api import logger, AstrBotConfig
from astrbot.core.message.message_event_result import MessageChain

from .Variable.sqlTable import VERIFY_LOG, VERIFY_USER_DATA, VERIFY_GROUP_LOG, REQUEID_TABLES
from .Variable.messageTemplate import help_menu, new_user_join

class LinkAmongUs(Star):
    def __init__(self, context: Context, config: AstrBotConfig): # AstrBotConfig 继承自 Dict，拥有字典的所有方法。
        super().__init__(context)
        self.db_pool = None
        self.session = None
        self.running = True  # 添加标志位控制定时任务循环
        # 加载配置
        self.config = config

        # 白名单设置
        self.WhitelistConfig: dict = self.config.get("WhitelistConfig")
        self.WhitelistConfig_WhitelistGroups: list = self.WhitelistConfig.get("WhitelistConfig_WhitelistGroups")
        self.WhitelistConfig_AllowPrivateMessage: bool = self.WhitelistConfig.get("WhitelistConfig_AllowPrivateMessage")

        # MySQL设置
        self.MySQLConfig: dict = self.config.get("MySQLConfig")
        self.MySQLConfig_Address: str = self.MySQLConfig.get("MySQLConfig_Address")
        self.MySQLConfig_Port: int = self.MySQLConfig.get("MySQLConfig_Port")
        self.MySQLConfig_UserName: str = self.MySQLConfig.get("MySQLConfig_UserName")
        self.MySQLConfig_UserPassword: str = self.MySQLConfig.get("MySQLConfig_UserPassword")
        self.MySQLConfig_Database: str = self.MySQLConfig.get("MySQLConfig_Database")
        
        # API设置
        self.APIConfig: dict = self.config.get("APIConfig")
        self.APIConfig_EndPoint: str = self.APIConfig.get("APIConfig_EndPoint")
        self.APIConfig_ServerName: str = self.APIConfig.get("APIConfig_ServerName")
        self.APIConfig_Key: str = self.APIConfig.get("APIConfig_Key")
        
        # 进群验证设置
        self.GroupVerifyConfig: dict = self.config.get("GroupVerifyConfig")
        self.GroupVerifyConfig_NewMemberNeedVerify: bool = self.GroupVerifyConfig.get("GroupVerifyConfig_NewMemberNeedVerify")
        self.GroupVerifyConfig_BanNewMemberDuration: int = self.GroupVerifyConfig.get("GroupVerifyConfig_BanNewMemberDuration")
        # 自动踢出设置
        self.GroupVerifyConfig_KickNewMemberConfig: dict = self.GroupVerifyConfig.get("GroupVerifyConfig_KickNewMemberConfig")
        self.KickNewMemberConfig_KickNewMemberIfNotVerify: int = self.GroupVerifyConfig_KickNewMemberConfig.get("KickNewMemberConfig_KickNewMemberIfNotVerify")
        self.KickNewMemberConfig_PollingInterval: int = self.GroupVerifyConfig_KickNewMemberConfig.get("KickNewMemberConfig_PollingInterval")

        # 验证设置
        self.VerifyConfig: dict = self.config.get("VerifyConfig")
        self.VerifyConfig_BlackFriendCode: list = self.VerifyConfig.get("VerifyConfig_BlackFriendCode")
        # 创建验证设置
        self.VerifyConfig_CreateVerifyConfig: dict = self.VerifyConfig.get("VerifyConfig_CreateVerifyConfig")
        self.CreateVerifyConfig_ApiTimeout: int = self.VerifyConfig_CreateVerifyConfig.get("CreateVerifyConfig_ApiTimeout")
        self.CreateVerifyConfig_TimeoutReminder: int = self.VerifyConfig_CreateVerifyConfig.get("CreateVerifyConfig_TimeoutReminder")
        self.CreateVerifyConfig_ProcessDuration: int = self.VerifyConfig_CreateVerifyConfig.get("CreateVerifyConfig_ProcessDuration")
        # 完成验证设置
        self.VerifyConfig_FinishVerifyConfig: dict = self.VerifyConfig.get("VerifyConfig_FinishVerifyConfig")
        self.FinishVerifyConfig_AutoCheck: bool = self.VerifyConfig_FinishVerifyConfig.get("FinishVerifyConfig_AutoCheck")

        # 生成帮助菜单
        star_metadata = context.get_registered_star("astrbot_plugin_link_amongus")
        self.help_menu = help_menu(
            plugin_name=star_metadata.name,
            version=star_metadata.version,
            author=star_metadata.author
        )

        logger.debug("[LinkAmongUs] 插件已启动。")
        
    async def initialize(self):
        """初始化插件"""
        # 检查配置合法性
        if self.CreateVerifyConfig_TimeoutReminder < 1 or self.CreateVerifyConfig_TimeoutReminder > self.CreateVerifyConfig_ProcessDuration:
          logger.fatal(f"[LinkAmongUs] 配置值非法：配置 CreateVerifyConfig_TimeoutReminder 合法值应在 1-{self.CreateVerifyConfig_ProcessDuration} 之间。")
          raise ValueError("配置 CreateVerifyConfig_TimeoutReminder 值非法。")
        if self.CreateVerifyConfig_ProcessDuration < 1 or self.CreateVerifyConfig_ProcessDuration > 600:
          logger.fatal("[LinkAmongUs] 配置值非法：配置 CreateVerifyConfig_ProcessDuration 合法值应在 1-600 之间。")
          raise ValueError("配置 CreateVerifyConfig_ProcessDuration 值非法。")
        if self.GroupVerifyConfig_BanNewMemberDuration < 1 or self.GroupVerifyConfig_BanNewMemberDuration > 30:
          logger.fatal("[LinkAmongUs] 配置值非法：配置 GroupVerifyConfig_BanNewMemberDuration 合法值应在 1-30 之间。")
          raise ValueError("配置 GroupVerifyConfig_BanNewMemberDuration 值非法。")
        if self.KickNewMemberConfig_PollingInterval < 1 or self.KickNewMemberConfig_PollingInterval > 30:
          logger.fatal("[LinkAmongUs] 配置值非法：配置 KickNewMemberConfig_PollingInterval 合法值应在 1-30 之间。")
          raise ValueError("配置 KickNewMemberConfig_PollingInterval 值非法。")
        if not self.APIConfig_EndPoint:
          logger.fatal("[LinkAmongUs] 配置值非法：配置 APIConfig_EndPoint 不能为空。")
          raise ValueError("配置 APIConfig_EndPoint 值非法。")
        if not self.APIConfig_Key:
          logger.fatal("[LinkAmongUs] 配置值非法：配置 APIConfig_Key 不能为空。")
          raise ValueError("配置 APIConfig_Key 值非法。")
        
        # 创建数据库连接池
        logger.debug(f"[LinkAmongUs] 正在尝试连接到 MySQL 服务器。")
        try: 
            self.db_pool = await aiomysql.create_pool(
                host=self.MySQLConfig_Address,
                port=self.MySQLConfig_Port,
                user=self.MySQLConfig_UserName,
                password=self.MySQLConfig_UserPassword,
                db=self.MySQLConfig_Database,
                charset='utf8mb4',
                autocommit=True
            )
        except Exception as e:
            logger.fatal(f"[LinkAmongUs] 连接至 MySQL 服务器时发生意外错误: {e}")
            raise ConnectionError("连接至 MySQL 服务器时发生意外错误。")
        
        # 数据表完整性校验
        logger.debug("[LinkAmongUs] 正在进行数据表完整性校验。")
        required_tables = REQUEID_TABLES
        async with self.db_pool.acquire() as conn:
            async with conn.cursor() as cursor:
                # 检查每个表是否存在
                for table_name in required_tables:
                    await cursor.execute(
                        "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = %s",
                        (table_name,)
                    )
                    result = await cursor.fetchone()
                    if result[0] == 0:
                        logger.debug(f"[LinkAmongUs] 数据表 {table_name} 不存在，正在创建...")
                        try:
                            if table_name == "VerifyUserData":
                                await cursor.execute(VERIFY_USER_DATA)
                            elif table_name == "VerifyLog":
                                await cursor.execute(VERIFY_LOG)
                            elif table_name == "VerifyGroupLog":
                                await cursor.execute(VERIFY_GROUP_LOG)
                            logger.debug(f"[LinkAmongUs] 数据表 {table_name} 创建成功。")
                        except Exception as e:
                            logger.fatal(f"[LinkAmongUs] 创建数据表 {table_name} 时发生意外错误: {e}")
                            raise aiomysql.MySQLError("创建数据表时发生意外错误。")
                    else:
                        logger.debug(f"[LinkAmongUs] 数据表 {table_name} 已存在。")
        
        # 创建HTTP会话
        self.session = aiohttp.ClientSession()
        
        # 轮询踢出未验证用户
        if self.KickNewMemberConfig_KickNewMemberIfNotVerify != 0:
            asyncio.create_task(self.scheduled_kick_unverified_users(AstrMessageEvent))
        
        logger.info("[LinkAmongUs] 插件初始化完成。")

    async def terminate(self):
        """停止插件"""
        # 停止定时任务
        self.running = False
        
        # 终止数据库连接
        if self.db_pool:
            self.db_pool.close()
            await self.db_pool.wait_closed()
        if self.session:
            await self.session.close()
        logger.debug("[LinkAmongUs] 插件已停止。")

    async def whitelist_check(self, event: AstrMessageEvent) -> bool:
        """白名单检查"""
        group_id = event.get_group_id()
        if group_id == "" and not self.WhitelistConfig_AllowPrivateMessage:
            logger.debug("[LinkAmongUs] 不允许在私聊中使用该命令，取消该任务。")
            return False
        if group_id != "" and self.WhitelistConfig_WhitelistGroups and group_id not in self.WhitelistConfig_WhitelistGroups:
            logger.debug(f"[LinkAmongUs] 群 {group_id} 不在白名单内，取消该任务。")
            return False
        return True

    async def check_user_exists_in_verify_data(self, user_qq_id: str) -> Optional[Dict[str, Any]]:
        """检查用户QQ号是否已存在于数据库"""
        logger.info(f"[LinkAmongUs] 正在验证用户 {user_qq_id} 是否已关联 Among Us 账号。")
        if not self.db_pool:
            logger.error("[LinkAmongUs] 未能验证用户是否已关联 Among Us 账号：数据库连接池未初始化。")
            return None
        async with self.db_pool.acquire() as conn:
            async with conn.cursor() as cursor:
                await cursor.execute(
                    "SELECT * FROM VerifyUserData WHERE UserQQID = %s",
                    (user_qq_id,)
                )
                result = await cursor.fetchone()
                if result:
                    columns = [desc[0] for desc in cursor.description]
                    result_dict = dict(zip(columns, result))
                    friend_code = result_dict.get('UserFriendCode')
                    logger.info(f"[LinkAmongUs] 用户 {user_qq_id} 已关联 Among Us 账号 {friend_code}。")
                    return result_dict
                logger.info(f"[LinkAmongUs] 用户 {user_qq_id} 尚未关联 Among Us 账号。")
                return None

    async def check_friend_code_exists_in_verify_data(self, friend_code: str) -> Optional[Dict[str, Any]]:
        """检查好友代码是否已存在于数据库"""
        logger.info(f"[LinkAmongUs] 正在验证好友代码 {friend_code} 是否已关联 QQ 号。")
        if not self.db_pool:
            logger.error("[LinkAmongUs] 未能验证好友代码是否已关联 QQ 号：数据库连接池未初始化。")
            return None        
        async with self.db_pool.acquire() as conn:
            async with conn.cursor() as cursor:
                await cursor.execute(
                    "SELECT * FROM VerifyUserData WHERE UserFriendCode = %s",
                    (friend_code,)
                )
                result = await cursor.fetchone()
                if result:
                    columns = [desc[0] for desc in cursor.description]
                    result_dict = dict(zip(columns, result))
                    qq_id = result_dict.get('UserQQID')
                    logger.info(f"[LinkAmongUs] 好友代码 {friend_code} 已关联 QQ 号 {qq_id}。")
                    return dict(zip(columns, result))
                logger.info(f"[LinkAmongUs] 好友代码 {friend_code} 尚未关联 QQ 号。")
                return None
                
    async def get_active_verify_request(self, user_qq_id: str) -> Optional[Dict[str, Any]]:
        """获取用户最新的进行中的验证请求"""
        logger.info(f"[LinkAmongUs] 正在获取用户 {user_qq_id} 最新的进行中的验证请求。")
        if not self.db_pool:
            logger.error("[LinkAmongUs] 未能获取活跃验证请求：数据库连接池未初始化。")
            return None
        async with self.db_pool.acquire() as conn:
            async with conn.cursor() as cursor:
                await cursor.execute(
                    "SELECT * FROM VerifyLog WHERE UserQQID = %s AND Status IN ('Created', 'Retrying') ORDER BY CreateTime DESC LIMIT 1",
                    (user_qq_id,)
                )
                result = await cursor.fetchone()
                if result:
                    columns = [desc[0] for desc in cursor.description]
                    logger.info(f"[LinkAmongUs] 已找到用户 {user_qq_id} 的最新活跃验证请求。")
                    return dict(zip(columns, result))
                logger.info(f"[LinkAmongUs] 用户 {user_qq_id} 没有活跃的验证请求。")
                return None

    async def update_verify_log_status(self, sql_id: int, status: str) -> bool:
        """更新验证日志状态"""
        if not self.db_pool:
            logger.error("[LinkAmongUs] 未能更新验证日志状态：数据库连接池未初始化。")
            return False
        logger.info(f"[LinkAmongUs] 正在将 ID {sql_id} 的验证日志状态更新为 {status}。")
        
        try:
            async with self.db_pool.acquire() as conn:
                async with conn.cursor() as cursor:
                    await cursor.execute(
                        "UPDATE VerifyLog SET Status = %s WHERE SQLID = %s",
                        (status, sql_id)
                    )
                    logger.info(f"[LinkAmongUs] 已将 ID {sql_id} 的验证日志更新为 {status}。")
                    return True
        except Exception as e:
            logger.error(f"[LinkAmongUs] 更新验证日志状态时发生错误: {e}")
            return False

    async def insert_verify_user_data(self, user_data: Dict[str, Any]) -> bool:
        """写入用户身份数据"""
        logger.info(f"[LinkAmongUs] 准备写入用户 {user_data.get('UserQQID')}({user_data.get('UserFriendCode')}) 的身份数据。")
        if not self.db_pool:
            logger.error("[LinkAmongUs] 未能写入用户身份数据：数据库连接池未建立。")
            return False
        try:
            async with self.db_pool.acquire() as conn:
                async with conn.cursor() as cursor:
                    await cursor.execute(
                        """INSERT INTO VerifyUserData 
                        (UserQQName, UserQQID, UserAmongUsName, UserFriendCode, UserPuid, 
                        UserHashedPuid, UserUdpPlatform, UserTokenPlatform, UserUdpIP, UserHttpIP) 
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                        (
                            user_data.get("UserQQName"),
                            user_data.get("UserQQID"),
                            user_data.get("UserAmongUsName"),
                            user_data.get("UserFriendCode"),
                            user_data.get("UserPuid"),
                            user_data.get("UserHashedPuid"),
                            user_data.get("UserUdpPlatform"),
                            user_data.get("UserTokenPlatform"),
                            user_data.get("UserUdpIP"),
                            user_data.get("UserHttpIP")
                        )
                    )
                    logger.info(f"[LinkAmongUs] 成功写入用户 {user_data.get('UserQQID')} 的身份验证数据。")
                    return True
        except Exception as e:
            logger.error(f"[LinkAmongUs] 插入用户身份数据时发生错误: {e}")
            return False

    @filter.command_group("verify")
    def verify(self):
        """插件命令列表"""
        pass

    @filter.platform_adapter_type(filter.PlatformAdapterType.AIOCQHTTP)
    @verify.command("create")
    async def verify_create(self, event: AstrMessageEvent, friend_code: str):
        """创建一个验证请求"""
        if not await self.whitelist_check(event):
            return

        user_qq_id = event.get_sender_id()

        # 校验好友代码格式
        if len(friend_code) < 9 and len(friend_code) > 25:
            logger.debug(f"[LinkAmongUs] 用户使用的好友代码长度超过限制，拒绝使用此好友代码创建验证请求。")
            yield event.plain_result("创建验证请求失败，此好友代码非法。")
            return
        import re
        pattern = r'^[A-Za-z]+#\d{4}$'
        if not re.match(pattern, friend_code):
            logger.debug(f"[LinkAmongUs] 用户使用的好友代码格式错误，拒绝使用此好友代码创建验证请求。")
            yield event.plain_result("创建验证请求失败，此好友代码非法。")
            return

        # 检查好友代码是否在黑名单中
        black_list = self.VerifyConfig_BlackFriendCode
        if friend_code in black_list:
            logger.debug(f"[LinkAmongUs] 用户使用的好友代码命中黑名单，拒绝使用此好友代码创建验证请求。")
            yield event.plain_result("创建验证请求失败，此好友代码非法。")
            return

        # 检查用户是否已关联账号
        existing_user = await self.check_user_exists_in_verify_data(user_qq_id)
        if existing_user:
            logger.debug(f"[LinkAmongUs] 用户 {user_qq_id} 已绑定 Among Us 账号 {existing_user['UserFriendCode']}，拒绝创建验证请求。")
            yield event.plain_result(
                f"创建验证请求失败，你的账号已绑定 {existing_user['UserFriendCode']}。\n"
                f"若要更换，请联系管理员。"
            )
            return
        existing_friend_code = await self.check_friend_code_exists_in_verify_data(friend_code)
        if existing_friend_code:
            logger.warning(f"[LinkAmongUs] 用户使用的好友代码已绑定 QQ号 {existing_friend_code['UserQQID']}，拒绝创建验证请求。")
            yield event.plain_result(
                f"创建验证请求失败，该好友代码已绑定 {existing_friend_code['UserQQID']}。\n"
                f"若要更换，请联系管理员。"
            )
            return

        # 检查用户是否有进行中的验证请求
        active_verify_request = await self.get_active_verify_request(user_qq_id)
        if active_verify_request:
            status = active_verify_request["Status"]
            create_time = active_verify_request["CreateTime"]
            verify_code = active_verify_request["VerifyCode"]
            friend_code = active_verify_request["UserFriendCode"]
            if status in ["Created", "Retrying"]:
                server_name = self.APIConfig_ServerName
                logger.warning(f"[LinkAmongUs] 用户 {user_qq_id} 已有进行中的验证请求，拒绝重复创建验证请求。")
                yield event.plain_result(
                    f"创建验证请求失败，你已于 {create_time} 使用 {friend_code} 创建了一个验证请求，需要加入服务器 {server_name} 房间 {verify_code} 以完成验证。\n"
                    f"请先完成或取消现有的验证请求。"
                )
                return

        # 创建验证请求
        logger.info(f"[LinkAmongUs] 用户 {user_qq_id} 使用 Among Us 账号 {friend_code} 创建了一个验证请求。")
        api_key = self.APIConfig_Key
        from .api import request_verify_api
        api_response = await request_verify_api(
            session=self.session,
            api_endpoint=self.APIConfig_EndPoint,
            api_timeout=self.CreateVerifyConfig_ApiTimeout,
            method="PUT",
            api_key=api_key,
            friend_code=friend_code
        )
        if not api_response:
            logger.warning("[LinkAmongUs] 创建验证请求失败，API 请求失败。")
            yield event.plain_result("创建验证请求失败，请求API时出现异常，请联系管理员。")
            return

        # 写入验证日志
        verify_code = api_response["VerifyCode"]
        logger.info(f"[LinkAmongUs] 正在写入用户 {user_qq_id} 的验证日志。")
        if not self.db_pool:
            logger.error("[LinkAmongUs] 未能写入验证日志：数据库连接池未初始化。")
            yield event.plain_result("创建验证请求失败，数据库连接池未初始化，请联系管理员。")
            return
        try:
            async with self.db_pool.acquire() as conn:
                async with conn.cursor() as cursor:
                    await cursor.execute(
                        "INSERT INTO VerifyLog (Status, UserQQID, UserFriendCode, VerifyCode) VALUES (%s, %s, %s, %s)",
                        ("Created", user_qq_id, friend_code, verify_code)
                    )
                    logger.info(f"[LinkAmongUs] 成功写入用户 {user_qq_id} 的验证日志。")
        except Exception as e:
            logger.error(f"[LinkAmongUs] 写入验证日志时发生错误: {e}")
            yield event.plain_result("创建验证请求失败，数据库写入异常，请联系管理员。")
            return

        # 发送成功消息
        process_duration = self.CreateVerifyConfig_ProcessDuration
        server_name = self.APIConfig_ServerName
        success_message = (
            f"成功创建验证请求，请在 {process_duration} 秒内使用账号 {friend_code} 加入 {server_name} 房间 {verify_code} 以完成验证。"
        )
        logger.info(f"[LinkAmongUs] 用户 {user_qq_id} 成功创建验证请求。")
        yield event.plain_result(success_message)

        # 启动超时检查任务
        umo = event.unified_msg_origin
        user_group_id = event.get_group_id()
        asyncio.create_task(self.verification_timeout_checker(user_qq_id, user_group_id, process_duration, umo))

    async def verification_timeout_checker(self, user_qq_id: str, user_group_id: str, timeout: int, umo: str):
        """验证超时检查任务"""
        logger.info(f"已启动用户 {user_qq_id} 的验证请求超时检查任务。")

        # 检查是否启用超时提醒
        try:
          if self.CreateVerifyConfig_TimeoutReminder != 0:
              reminder_time = timeout - self.CreateVerifyConfig_TimeoutReminder
              await asyncio.sleep(reminder_time)

              verify_log = await self.get_active_verify_request(user_qq_id)
              # 发送超时提醒
              if verify_log and verify_log["Status"] in ["Created", "Retrying"]:
                messageChain_Group = [
                  Comp.At(qq=user_qq_id),
                  Comp.Plain("\n你的验证请求即将过期，请尽快完成验证！\n如果已使用Among Us完成了验证，请发送/verify finish命令。")
                ]
                messageChain_Private = [
                    Comp.Plain("你的验证请求即将过期，请尽快完成验证！\n如果已使用Among Us完成了验证，请发送/verify finish命令。")
                ]
                if user_group_id == "":
                    messageChain = MessageChain(chain=messageChain_Private)
                else:
                    messageChain = MessageChain(chain=messageChain_Group)
                try:
                    await self.context.send_message(umo, messageChain)
                    logger.debug(f"[LinkAmongUs] 已提醒用户 {user_qq_id} 完成验证请求。")
                except Exception as e:
                    logger.warning(f"[LinkAmongUs] 发送超时提醒消息失败: {e}")
                    logger.warning(f"[LinkAmongUs] 将忽略超时提醒问题，继续执行超时检查。")

                # 等待剩余时间
                await asyncio.sleep(self.CreateVerifyConfig_TimeoutReminder)
              else:
                logger.debug(f"用户 {user_qq_id} 已完成验证请求，结束超时检查任务。")
                return
          else:
            await asyncio.sleep(timeout)
        
          # 最终的超时检查
          verify_log = await self.get_active_verify_request(user_qq_id)
          if verify_log and verify_log["Status"] in ["Created", "Retrying"]:
            logger.info(f"[LinkAmongUs] 用户 {user_qq_id} 的验证请求已超时。")
            await self.update_verify_log_status(verify_log["SQLID"], "Expired")
          else:
            logger.debug(f"用户 {user_qq_id} 已完成验证请求，结束超时检查任务。")
        except Exception as e:
          logger.error(f"[LinkAmongUs] 超时检查任务发生意外错误：{e}")
          try: 
            errorMessageChain = [
              Comp.Plain("发生意外错误，请联系管理员。\n插件将尝试直接取消你的验证请求，如未正常工作，请发送 /verify cancel 命令。")
            ]
            await self.context.send_message(umo, errorMessageChain)
          except Exception as e:
            logger.warning(f"[LinkAmongUs] 发送错误消息失败: {e}")
            logger.warning(f"[LinkAmongUs] 将忽略错误，将继续取消用户 {user_qq_id} 的验证请求。")
          try:
            verify_log = await self.get_active_verify_request(user_qq_id)
            await self.update_verify_log_status(verify_log["SQLID"], "Cancelled")
            logger.warning(f"[LinkAmongUs] 用户 {user_qq_id} 的验证请求因内部错误被取消。")
          except Exception as e:
            logger.error(f"[LinkAmongUs] 取消用户 {user_qq_id} 的验证请求时发生意外错误：{e}")

    @filter.platform_adapter_type(filter.PlatformAdapterType.AIOCQHTTP)
    @verify.command("finish")
    async def verify_finish(self, event: AstrMessageEvent):
        """完成一个验证请求"""
        if not await self.whitelist_check(event):
            return
            
        user_qq_id = event.get_sender_id()
        # 检查用户是否有活跃的验证请求
        verify_log = await self.get_active_verify_request(user_qq_id)
        if not verify_log:
            logger.debug(f"[LinkAmongUs] 用户 {user_qq_id} 没有活跃的验证请求，拒绝完成验证请求。")
            yield event.plain_result("你还没有创建验证请求，或是该验证请求已过期。")
            return

        logger.info(f"[LinkAmongUs] 用户 {user_qq_id} 请求完成验证。")
        # 查询验证状态
        api_key = self.APIConfig_Key
        from .api import request_verify_api
        api_response = await request_verify_api(
            session=self.session,
            api_endpoint=self.APIConfig_EndPoint,
            api_timeout=self.CreateVerifyConfig_ApiTimeout,
            method="GET",
            api_key=api_key,
            verify_code=verify_log["VerifyCode"]
        )
        if not api_response:
            logger.warning("[LinkAmongUs] 完成验证请求失败，API 请求失败。")
            yield event.plain_result("检查验证失败，请求API时出现异常，请联系管理员。")
            return
        verify_status = api_response.get("VerifyStatus")
        logger.debug(f"[LinkAmongUs] 已查询到用户 {user_qq_id} 的验证状态：{verify_status}。")
        
        # 根据API返回的状态处理
        if verify_status == "NotVerified":
            await self.update_verify_log_status(verify_log["SQLID"], "Retrying")
            logger.info(f"[LinkAmongUs] 用户 {user_qq_id} 的验证请求为未完成，拒绝完成验证请求。")
            yield event.plain_result("验证失败，你还没有进行验证。")
        elif verify_status == "HttpPending":
            await self.update_verify_log_status(verify_log["SQLID"], "Retrying")
            logger.info(f"[LinkAmongUs] 用户 {user_qq_id} 的验证请求为未完成，拒绝完成验证请求。")
            yield event.plain_result("验证失败，请加入房间而不是仅搜索。")
        elif verify_status == "Verified":
            # 额外检查用户是否已关联账号
            existing_user = await self.check_user_exists_in_verify_data(user_qq_id)
            existing_friend_code = await self.check_friend_code_exists_in_verify_data(api_response.get("FriendCode"))
            if existing_user or existing_friend_code:
                await self.api_verify_request("DELETE", api_key, verify_code=verify_log["VerifyCode"])
                await self.update_verify_log_status(verify_log["SQLID"], "Cancelled")
                error_message = "验证失败，"
                if existing_user:
                    error_message += f"你的QQ号已绑定 {existing_user['UserFriendCode']}。"
                if existing_friend_code:
                    if existing_user:
                        error_message += " "
                    error_message += f"该好友代码已绑定 {existing_friend_code['UserQQID']}。"
                error_message += "\n若要更换，请联系管理员。"
                
                logger.warning(f"[LinkAmongUs] 用户 {user_qq_id} 发生数据冲突，拒绝完成验证请求。")
                yield event.plain_result(error_message)
                return
            
            # 获取用户名称
            # event.get_sender_name() 方法不可靠，其无法正常获取临时会话的用户名称。
            logger.debug(f"[LinkAmongUs] 正在获取用户 {user_qq_id} 的名称。")
            try: 
                from astrbot.core.platform.sources.aiocqhttp.aiocqhttp_message_event import AiocqhttpMessageEvent
                assert isinstance(event, AiocqhttpMessageEvent)
                client = event.bot
                stranger_info = await client.get_stranger_info(
                    user_id=int(user_qq_id), no_cache=True
                )
                user_qq_name = stranger_info.get("nickname")
                logger.debug("[LinkAmongUs] 成功获取用户名称。")
            except Exception as e:
                logger.warning(f"[LinkAmongUs] 获取用户 {user_qq_id} 的名称时发生意外错误，将使用备用方法获取名称：{e}")
                user_qq_name = event.get_sender_name()
            
            # 写入用户数据
            user_data = {
                "UserQQName": user_qq_name,
                "UserQQID": user_qq_id,
                "UserAmongUsName": api_response.get("PlayerName"),
                "UserFriendCode": api_response.get("FriendCode"),
                "UserPuid": api_response.get("Puid"),
                "UserHashedPuid": api_response.get("HashedPuid"),
                "UserUdpPlatform": api_response.get("UdpPlatform"),
                "UserTokenPlatform": api_response.get("TokenPlatform"),
                "UserUdpIP": api_response.get("UdpIp"),
                "UserHttpIP": api_response.get("HttpIp")
            }
            
            if await self.insert_verify_user_data(user_data):
                await self.api_verify_request("DELETE", api_key, verify_code=verify_log["VerifyCode"])
                await self.update_verify_log_status(verify_log["SQLID"], "Verified")
                success_message = (
                    f"验证成功！已将 {user_data['UserAmongUsName']}({user_data['UserFriendCode']}) 关联 QQ {user_data['UserQQID']}。"
                )
                logger.info(f"[LinkAmongUs] 成功将用户 {user_qq_id} 关联好友代码 {user_data['UserFriendCode']}。")
                yield event.plain_result(success_message)
            else:
                logger.error(f"[LinkAmongUs] 用户 {user_qq_id} 验证数据写入失败。")
                yield event.plain_result("验证失败，数据库写入异常，请联系管理员。")
        elif verify_status == "Expired":
            await self.update_verify_log_status(verify_log["SQLID"], "Expired")
            logger.info(f"[LinkAmongUs] 用户 {user_qq_id} 验证请求已过期，拒绝完成验证请求。")
            yield event.plain_result("验证失败，请求已过期，请重新创建验证请求。")
        else:
            logger.warning(f"[LinkAmongUs] 用户 {user_qq_id} 验证请求状态 {verify_status} 非法，拒绝完成验证请求。")
            yield event.plain_result(f"验证失败，你的验证请求状态非法，请联系管理员。")

    @filter.platform_adapter_type(filter.PlatformAdapterType.AIOCQHTTP)
    @filter.permission_type(filter.PermissionType.ADMIN)
    @verify.command("clean")
    async def verify_clean(self, event: AstrMessageEvent):
        """清理数据库中的非法验证请求"""
        process_duration = self.CreateVerifyConfig_ProcessDuration
        logger.info(f"[LinkAmongUs] 管理员请求了清理数据库中的非法验证请求。")
        if not self.db_pool:
            logger.error("[LinkAmongUs] 清理数据库非法验证请求失败：数据库连接池未初始化。")
            yield event.plain_result("清理失败，数据库连接池未初始化。")
            return

        try:
            current_time = datetime.now()
            
            # 查询所有状态为Created或Retrying的记录
            async with self.db_pool.acquire() as conn:
                async with conn.cursor() as cursor:
                    await cursor.execute(
                        "SELECT SQLID, CreateTime, Status, UserQQID, UserFriendCode FROM VerifyLog WHERE Status IN ('Created', 'Retrying')"
                    )
                    results = await cursor.fetchall()
                    if not results:
                        logger.info("[LinkAmongUs] 未找到非法验证状态请求。")
                        yield event.plain_result("没有找到需要清理的验证请求。")
                        return
                    expired_count = 0
                    columns = [desc[0] for desc in cursor.description]
                    logger.debug(f"[LinkAmongUs] 已找到 {len(results)} 条待检查的验证请求。")

                    # 检查每条记录是否超时
                    for row in results:
                        record = dict(zip(columns, row))
                        create_time = record["CreateTime"]
                        time_diff = (current_time - create_time).total_seconds()
                        if time_diff > process_duration:
                            await self.update_verify_log_status(record["SQLID"], "Expired")
                            expired_count += 1
                            logger.debug(f"[LinkAmongUs] 验证请求 ID {record['SQLID']} 已过期，正在处理。")
                    
                    logger.info(f"[LinkAmongUs] 清理非法验证请求完成，共处理 {len(results)} 条验证请求，找到并处理了 {expired_count} 条非法验证请求。")
                    yield event.plain_result(f"清理完成，共处理 {len(results)} 条验证请求，找到并处理了 {expired_count} 条非法验证请求。")
                    
        except Exception as e:
            logger.error(f"[LinkAmongUs] 清理非法验证请求时发生错误: {e}")
            yield event.plain_result("清理失败，发生意外错误，请查看日志。")

    @filter.platform_adapter_type(filter.PlatformAdapterType.AIOCQHTTP)
    @filter.permission_type(filter.PermissionType.ADMIN)
    @verify.command("query")
    async def verify_query(self, event: AstrMessageEvent, query_value: str):
        """查询指定用户的账号关联信息"""
        if not await self.whitelist_check(event):
            return
            
        # 参数格式校验
        import re
        friend_code_pattern = r'^[A-Za-z]+#\d{4}$'
        is_friend_code = len(query_value) <= 25 and re.match(friend_code_pattern, query_value)
        is_qq_number = query_value.isdigit() and 5 <= len(query_value) <= 13
        if not is_friend_code and not is_qq_number:
            logger.debug(f"[LinkAmongUs] 管理员查询的用户非法，拒绝使用此参数查询用户信息。")
            yield event.plain_result("查询参数非法。")
            return
            
        # 查询用户绑定信息
        logger.info(f"[LinkAmongUs] 正在查询用户 {query_value} 的绑定信息。")
        if not self.db_pool:
            logger.error("[LinkAmongUs] 未能查询用户绑定信息：数据库连接池未初始化。")
            yield event.plain_result("查询失败，数据库连接池未初始化。")
            return
        
        async with self.db_pool.acquire() as conn:
            async with conn.cursor() as cursor:
                await cursor.execute(
                    "SELECT UserQQID, UserAmongUsName, UserFriendCode, LastUpdated, UserHashedPuid, UserTokenPlatform FROM VerifyUserData WHERE UserQQID = %s",
                    (query_value,)
                )
                result = await cursor.fetchone()
                if not result:
                    await cursor.execute(
                        "SELECT UserQQID, UserAmongUsName, UserFriendCode, LastUpdated, UserHashedPuid, UserTokenPlatform FROM VerifyUserData WHERE UserFriendCode = %s",
                        (query_value,)
                    )
                    result = await cursor.fetchone()
                
                if result:
                    columns = [desc[0] for desc in cursor.description]
                    user_data = dict(zip(columns, result))
                    logger.info(f"[LinkAmongUs] 成功查询到用户 {query_value} 的绑定信息。")
                    message = (
                        f"用户 {user_data['UserQQID']} 账号关联信息：\n"
                        f"账号名称：{user_data['UserAmongUsName']}\n"
                        f"好友代码: {user_data['UserFriendCode']} ({user_data['UserHashedPuid']})\n"
                        f"账号平台：{user_data['UserTokenPlatform']}\n"
                        f"关联时间: {user_data['LastUpdated'].strftime('%Y-%m-%d %H:%M:%S')}"
                    )
                    yield event.plain_result(message)
                else:
                    logger.info(f"[LinkAmongUs] 未找到用户 {query_value} 的绑定信息。")
                    yield event.plain_result(f"未找到用户 {query_value} 的绑定信息。")

    @filter.platform_adapter_type(filter.PlatformAdapterType.AIOCQHTTP)
    @verify.command("cancel")
    async def verify_cancel(self, event: AstrMessageEvent):
        """取消用户当前的验证请求"""
        if not await self.whitelist_check(event):
            return
        
        # 检查是否有活跃的验证请求
        user_qq_id = event.get_sender_id()
        verify_log = await self.get_active_verify_request(user_qq_id)
        if not verify_log:
            logger.debug(f"[LinkAmongUs] 用户 {user_qq_id} 没有活跃的验证请求，拒绝取消验证请求。")
            yield event.plain_result("你没有进行中的验证请求需要取消。")
            return

        logger.info(f"[LinkAmongUs] 用户 {user_qq_id} 请求取消验证请求。")
        api_key = self.APIConfig_Key
        verify_code = verify_log["VerifyCode"]
        from .api import request_verify_api
        delete_success = await request_verify_api(
            session=self.session,
            api_endpoint=self.APIConfig_EndPoint,
            api_timeout=self.CreateVerifyConfig_ApiTimeout,
            method="DELETE",
            api_key=api_key,
            verify_code=verify_code
        )
        update_success = await self.update_verify_log_status(verify_log["SQLID"], "Cancelled")
        if delete_success and update_success:
            logger.info(f"[LinkAmongUs] 用户 {user_qq_id} 成功取消验证请求 {verify_code}。")
            yield event.plain_result(f"已成功取消你于 {verify_log['CreateTime'].strftime('%Y-%m-%d %H:%M:%S')} 使用账号 {verify_log['UserFriendCode']} 创建的验证请求。")
        else:
            logger.warning(f"[LinkAmongUs] 未能取消用户 {user_qq_id} 的验证请求。")
            yield event.plain_result("取消请求时发生意外错误，请联系管理员。")

    @filter.platform_adapter_type(filter.PlatformAdapterType.AIOCQHTTP)
    @verify.command("info")
    async def verify_info(self, event: AstrMessageEvent):
        """查询当前用户的账号关联信息"""
        if not await self.whitelist_check(event):
            return
            
        user_qq_id = event.get_sender_id()
        logger.info(f"[LinkAmongUs] 正在查询用户 {user_qq_id} 的绑定信息。")
        if not self.db_pool:
            logger.error("[LinkAmongUs] 未能查询用户绑定信息：数据库连接池未初始化。")
            yield event.plain_result("查询失败，数据库连接池未初始化。")
            return
        async with self.db_pool.acquire() as conn:
            async with conn.cursor() as cursor:
                await cursor.execute(
                    "SELECT UserAmongUsName, UserFriendCode, LastUpdated, UserHashedPuid, UserTokenPlatform FROM VerifyUserData WHERE UserQQID = %s",
                    (user_qq_id,)
                )
                result = await cursor.fetchone()
                if result:
                    columns = [desc[0] for desc in cursor.description]
                    user_data = dict(zip(columns, result))
                    logger.info(f"[LinkAmongUs] 成功查询到用户 {user_qq_id} 的绑定信息。")
                    message = (
                        f"你的账号关联信息：\n"
                        f"账号名称：{user_data['UserAmongUsName']}\n"
                        f"好友代码：{user_data['UserFriendCode']} ({user_data['UserHashedPuid']})\n"
                        f"账号平台：{user_data['UserTokenPlatform']}\n"
                        f"关联时间：{user_data['LastUpdated'].strftime('%Y-%m-%d %H:%M:%S')}"
                    )
                    yield event.plain_result(message)
                else:
                    logger.info(f"[LinkAmongUs] 用户 {user_qq_id} 尚未绑定 Among Us 账号。")
                    yield event.plain_result(f"你还未绑定 Among Us 账号。")

    @filter.platform_adapter_type(filter.PlatformAdapterType.AIOCQHTTP)
    @verify.command("help")
    async def verify_help(self, event: AstrMessageEvent):
        """发送帮助菜单"""
        if not await self.whitelist_check(event):
            return
        yield event.plain_result(self.help_menu)

    @filter.platform_adapter_type(filter.PlatformAdapterType.AIOCQHTTP)
    # 只允许私聊
    @filter.event_message_type(filter.EventMessageType.PRIVATE_MESSAGE)
    @verify.command("unban")
    async def verify_unban(self, event: AstrMessageEvent):
        """尝试解除入群验证禁言"""
        if not await self.whitelist_check(event):
            return
            
        user_qq_id = event.get_sender_id()
        logger.info(f"[LinkAmongUs] 用户 {user_qq_id} 请求解除入群验证禁言。")
        
        # 检查用户是否已关联账号
        existing_user = await self.check_user_exists_in_verify_data(user_qq_id)
        if not existing_user:
            logger.info(f"[LinkAmongUs] 用户 {user_qq_id} 尚未关联账号，拒绝解除禁言。")
            yield event.plain_result("解除禁言失败，你还未进行账号关联。")
            return
            
        if not self.db_pool:
            logger.error("[LinkAmongUs] 未能查询入群验证日志：数据库连接池未初始化。")
            yield event.plain_result("解除禁言失败，数据库连接池未初始化。")
            return
            
        try:
            async with self.db_pool.acquire() as conn:
                async with conn.cursor() as cursor:
                    await cursor.execute(
                        "SELECT SQLID, BanGroupID FROM VerifyGroupLog WHERE VerifyUserID = %s AND Status = %s",
                        (user_qq_id, "Banned")
                    )

                    banned_logs = await cursor.fetchall()
                    if not banned_logs:
                        logger.info(f"[LinkAmongUs] 未找到用户 {user_qq_id} 的入群验证禁言记录。")
                        yield event.plain_result("未找到你正在进行中的入群验证。\n如果确实仍在被禁言，请联系对应群聊的管理员手动解禁。")
                        return

                    unbanned_groups = []
                    for log in banned_logs:
                        log_id = log[0]
                        group_id = log[1]
                        try:
                            from astrbot.core.platform.sources.aiocqhttp.aiocqhttp_message_event import AiocqhttpMessageEvent
                            assert isinstance(event, AiocqhttpMessageEvent)
                            await event.bot.set_group_ban(
                                group_id=int(group_id),
                                user_id=int(user_qq_id),
                                duration=0
                            )
                            logger.debug(f"[LinkAmongUs] 已解除用户 {user_qq_id} 在群 {group_id} 的禁言。")
                            unbanned_groups.append(group_id)
                            await cursor.execute(
                                "UPDATE VerifyGroupLog SET Status = %s WHERE SQLID = %s",
                                ("Unbanned", log_id)
                            )
                        except Exception as e:
                            logger.error(f"[LinkAmongUs] 解除用户 {user_qq_id} 在群 {group_id} 的禁言时发生意外错误: {e}")
                        yield event.plain_result("已尝试解除你的入群验证禁言，如不生效请联系群聊管理员手动解除。")
                        
        except Exception as e:
            logger.error(f"[LinkAmongUs] 处理用户 {user_qq_id} 的解除禁言请求时发生错误: {e}")
            yield event.plain_result("解除禁言失败，发生意外错误，请联系管理员。")

    @filter.platform_adapter_type(filter.PlatformAdapterType.AIOCQHTTP)
    @filter.event_message_type(filter.EventMessageType.ALL)
    async def group_increase(self, event: AstrMessageEvent):
        """接收新成员入群事件以触发入群验证"""
        if not self.GroupVerifyConfig_NewMemberNeedVerify:
            return
        # 筛选消息
        if not hasattr(event, "message_obj") or not hasattr(event.message_obj, "raw_message"):
            return
        raw_message = event.message_obj.raw_message
        if not raw_message or not isinstance(raw_message, dict):
            return

        # 筛选事件
        if raw_message.get("post_type") != "notice":
            return
        if raw_message.get("notice_type") != "group_increase":
            return
        if not await self.whitelist_check(event):
            return
            
        # 获取群号和用户QQ号
        group_id = str(raw_message.get("group_id"))
        user_qq_id = str(raw_message.get("user_id"))
        
        logger.debug(f"[LinkAmongUs] 新成员 {user_qq_id} 加入了群 {group_id}。")

        user_data = await self.check_user_exists_in_verify_data(user_qq_id)
        if user_data:
            logger.debug(f"[LinkAmongUs] 用户 {user_qq_id} 已关联 Among Us 账号，跳过入群验证流程。")
            return
            
        # 入群验证
        logger.info(f"[LinkAmongUs] 准备为成员 {user_qq_id} 创建入群验证。")
        if not self.db_pool:
            logger.error("[LinkAmongUs] 未能写入验证日志：数据库连接池未初始化。")
            return
            
        try:
            # 计算踢出时间
            kick_duration = self.KickNewMemberConfig_KickNewMemberIfNotVerify
            from datetime import timedelta
            kick_time = datetime.now() + timedelta(days=kick_duration)
            
            async with self.db_pool.acquire() as conn:
                async with conn.cursor() as cursor:
                    # 写入验证日志
                    await cursor.execute(
                        "INSERT INTO VerifyGroupLog (Status, VerifyUserID, BanGroupID, KickTime) VALUES (%s, %s, %s, %s)",
                        ("Created", user_qq_id, group_id, kick_time)
                    )

                    await cursor.execute("SELECT LAST_INSERT_ID()")
                    result = await cursor.fetchone()
                    log_id = result[0]

                    # 禁言用户
                    ban_seconds = self.GroupVerifyConfig_BanNewMemberDuration * 24 * 60 * 60  # 转换为秒
                    try:
                        from astrbot.core.platform.sources.aiocqhttp.aiocqhttp_message_event import AiocqhttpMessageEvent
                        assert isinstance(event, AiocqhttpMessageEvent)
                        await event.bot.set_group_ban(
                            group_id=int(group_id),
                            user_id=int(user_qq_id),
                            duration=ban_seconds
                        )
                        logger.debug(f"[LinkAmongUs] 已禁言成员 {user_qq_id}。")
                    except Exception as e:
                        logger.error(f"[LinkAmongUs] 禁言用户 {user_qq_id} 时发生错误: {e}")
                        return
                    await cursor.execute(
                        "UPDATE VerifyGroupLog SET Status = %s WHERE SQLID = %s",
                        ("Banned", log_id)
                    )
                    yield event.chain_result(new_user_join(user_qq_id))
                    
        except Exception as e:
            logger.error(f"[LinkAmongUs] 处理用户 {user_qq_id} 入群验证时发生错误: {e}")

    @filter.platform_adapter_type(filter.PlatformAdapterType.AIOCQHTTP)
    @filter.event_message_type(filter.EventMessageType.ALL)
    async def group_decrease(self, event: AstrMessageEvent):
        """处理成员退群事件"""
        if not self.GroupVerifyConfig_NewMemberNeedVerify:
            return
        # 筛选消息
        if not hasattr(event, "message_obj") or not hasattr(event.message_obj, "raw_message"):
            return
        raw_message = event.message_obj.raw_message
        if not raw_message or not isinstance(raw_message, dict):
            return

        # 筛选事件
        if raw_message.get("post_type") != "notice":
            return
        if raw_message.get("notice_type") != "group_increase":
            return
        if not await self.whitelist_check(event):
            return

        # 获取群号和用户QQ号
        group_id = str(raw_message.get("group_id"))
        user_qq_id = str(raw_message.get("user_id"))

        logger.debug(f"[LinkAmongUs] 成员 {user_qq_id} 退出了群 {group_id}。")
        
        if not self.db_pool:
            logger.error("[LinkAmongUs] 未能更新验证日志：数据库连接池未初始化。")
            return
            
        try:
            logger.info(f"[LinkAmongUs] 准备取消用户 {user_qq_id} 在群 {group_id} 的入群验证。")
            async with self.db_pool.acquire() as conn:
                async with conn.cursor() as cursor:
                    # 查找验证日志
                    await cursor.execute(
                        "SELECT SQLID, Status FROM VerifyGroupLog WHERE VerifyUserID = %s AND BanGroupID = %s",
                        (user_qq_id, group_id)
                    )
                    log = await cursor.fetchone()
                    if not log:
                        logger.debug(f"[LinkAmongUs] 未找到用户 {user_qq_id} 在群 {group_id} 的验证日志。")
                        return
                        
                    # 取消入群验证
                    log_id = log[0]
                    status = log[1]
                    if status in ["Created", "Banned"]:
                        await cursor.execute(
                            "UPDATE VerifyGroupLog SET Status = %s WHERE SQLID = %s",
                            ("Cancelled", log_id)
                        )
                        logger.info(f"[LinkAmongUs] 已取消成员 {user_qq_id} 在群 {group_id} 的入群验证。")
                        
        except Exception as e:
            logger.error(f"[LinkAmongUs] 处理用户 {user_qq_id} 退群 {group_id} 事件时发生错误: {e}")

    async def scheduled_kick_unverified_users(self, event: AstrMessageEvent):
        """定时任务：检查并踢出未验证的用户"""
        logger.info("[LinkAmongUs] 已启动未验证成员超时检查。")

        while self.running:  # 使用self.running标志位控制循环
            try:
                logger.debug("[LinkAmongUs] 正在准备未验证成员超时检查。")
                if not self.db_pool:
                    logger.error("[LinkAmongUs] 未能进行未验证成员超时检查，数据库连接池未初始化。")
                    polling_interval = self.KickNewMemberConfig_PollingInterval
                    await asyncio.sleep(polling_interval * 3600)
                    continue

                # 查找需要踢出的成员
                current_time = datetime.now()
                async with self.db_pool.acquire() as conn:
                    async with conn.cursor() as cursor:
                        await cursor.execute(
                            "SELECT SQLID, VerifyUserID, BanGroupID FROM VerifyGroupLog WHERE Status = %s AND KickTime <= %s",
                            ("Banned", current_time)
                        )
                        users_to_kick = await cursor.fetchall()
                        
                        if not users_to_kick:
                            logger.debug("[LinkAmongUs] 没有需要踢出的未验证成员。")
                        else:
                            logger.debug(f"[LinkAmongUs] 已找到 {len(users_to_kick)} 个需要踢出的未验证成员。")

                            # 踢出用户
                            for user in users_to_kick:
                                log_id = user[0]
                                user_qq_id = user[1]
                                group_id = user[2]
                                
                                try:
                                    # 尝试踢出用户
                                    logger.info(f"[LinkAmongUs] 准备踢出用户 {user_qq_id} 从群 {group_id}。")
                                    from astrbot.core.platform.sources.aiocqhttp.aiocqhttp_message_event import AiocqhttpMessageEvent
                                    assert isinstance(event, AiocqhttpMessageEvent)
                                    await event.bot.set_group_kick(
                                        group_id=int(group_id),
                                        user_id=int(user_qq_id),
                                        reject_add_request=False
                                    )
                                    
                                    # 更新入群验证日志
                                    await cursor.execute(
                                        "UPDATE VerifyGroupLog SET Status = %s WHERE SQLID = %s",
                                        ("Kicked", log_id)
                                    )
                                    logger.info(f"[LinkAmongUs] 已在群 {group_id} 踢出用户 {user_qq_id}。")
                                    
                                except Exception as e:
                                    logger.error(f"[LinkAmongUs] 在群 {group_id} 踢出用户 {user_qq_id} 时发生意外错误: {e}")
                                    
                        logger.debug(f"[LinkAmongUs] 已完成未验证成员超时检查。")
            except Exception as e:
                logger.error(f"[LinkAmongUs] 定时任务执行时发生错误: {e}")

            # 检查是否应继续执行任务
            if not self.running:
                logger.info("[LinkAmongUs] 已停止未验证成员超时检查。")
                break
                    
            # 等待
            polling_interval = self.KickNewMemberConfig_PollingInterval
            await asyncio.sleep(polling_interval * 3600)