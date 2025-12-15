import asyncio
import aiohttp
import aiomysql
import astrbot.api.message_components as Comp

from datetime import datetime
from astrbot.api.event import filter, AstrMessageEvent
from astrbot.api.star import Context, Star
from astrbot.api import logger, AstrBotConfig
from astrbot.core.message.message_event_result import MessageChain

from .variable.sqlTable import VERIFY_LOG, VERIFY_USER_DATA, VERIFY_GROUP_LOG, REQUEID_TABLES
from .variable.messageTemplate import help_menu, new_user_join
from .function.api.databaseManage import database_manage
from .function.api.verifyRequest import request_verify_api
from .function.func import friend_code_cheker, verification_timeout_checker

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
          raise ValueError("配置 CreateVerifyConfig_TimeoutReminder 值非法")
        if self.CreateVerifyConfig_ProcessDuration < 1 or self.CreateVerifyConfig_ProcessDuration > 600:
          logger.fatal("[LinkAmongUs] 配置值非法：配置 CreateVerifyConfig_ProcessDuration 合法值应在 1-600 之间。")
          raise ValueError("配置 CreateVerifyConfig_ProcessDuration 值非法")
        if self.GroupVerifyConfig_BanNewMemberDuration < 1 or self.GroupVerifyConfig_BanNewMemberDuration > 30:
          logger.fatal("[LinkAmongUs] 配置值非法：配置 GroupVerifyConfig_BanNewMemberDuration 合法值应在 1-30 之间。")
          raise ValueError("配置 GroupVerifyConfig_BanNewMemberDuration 值非法")
        if self.KickNewMemberConfig_PollingInterval < 1 or self.KickNewMemberConfig_PollingInterval > 30:
          logger.fatal("[LinkAmongUs] 配置值非法：配置 KickNewMemberConfig_PollingInterval 合法值应在 1-30 之间。")
          raise ValueError("配置 KickNewMemberConfig_PollingInterval 值非法")
        if not self.APIConfig_EndPoint:
          logger.fatal("[LinkAmongUs] 配置值非法：配置 APIConfig_EndPoint 不能为空。")
          raise ValueError("配置 APIConfig_EndPoint 值非法")
        if not self.APIConfig_Key:
          logger.fatal("[LinkAmongUs] 配置值非法：配置 APIConfig_Key 不能为空。")
          raise ValueError("配置 APIConfig_Key 值非法")
        
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
            raise ConnectionError("连接至 MySQL 服务器时发生意外错误")
        
        # 数据表完整性校验
        logger.debug("[LinkAmongUs] 正在进行数据表完整性校验。")
        required_tables = REQUEID_TABLES
        
        for table_name in required_tables:
            if table_name == "VerifyUserData":
                table_structure = VERIFY_USER_DATA
            elif table_name == "VerifyLog":
                table_structure = VERIFY_LOG
            elif table_name == "VerifyGroupLog":
                table_structure = VERIFY_GROUP_LOG
            
            check_result = await database_manage(self.db_pool, table_name, "check", structure=table_structure)
            if not check_result["success"]:
                logger.fatal(f"[LinkAmongUs] 校验数据表 {table_name} 时发生意外错误。")
                raise aiomysql.MySQLError("校验数据表时发生意外错误")
            
            if check_result["data"].get("created"):
                logger.debug(f"[LinkAmongUs] 数据表 {table_name} 创建成功。")
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

    @filter.command_group("verify")
    def verify(self):
        pass

    @filter.platform_adapter_type(filter.PlatformAdapterType.AIOCQHTTP)
    @verify.command("create")
    async def verify_create(self, event: AstrMessageEvent, friend_code: str):
        """创建一个验证请求"""
        if not await self.whitelist_check(event):
            return

        user_qq_id = event.get_sender_id()
        logger.info(f"[LinkAmongUs] 用户 {user_qq_id} 请求创建验证请求。")

        # 检查用户是否有进行中的验证请求
        active_verify_request_result = await database_manage(self.db_pool, "VerifyLog", "get", latest=True, user_qq_id=user_qq_id)
        active_verify_request = active_verify_request_result["data"] if active_verify_request_result["success"] and active_verify_request_result["data"] else None
        if active_verify_request:
            status = active_verify_request["Status"]
            create_time = active_verify_request["CreateTime"]
            verify_code = active_verify_request["VerifyCode"]
            friend_code = active_verify_request["UserFriendCode"]
            if status in ["Created", "Retrying"]:
                server_name = self.APIConfig_ServerName
                logger.info(f"[LinkAmongUs] 用户 {user_qq_id} 已有进行中的验证请求，拒绝重复创建验证请求。")
                return event.plain_result(f"你已于 {create_time} 使用 {friend_code} 创建了一个验证请求，需要加入服务器 {server_name} 房间 {verify_code} 以完成验证。\n请先完成或取消该请求。")

        # 检查用户是否已关联账号
        user_check = await database_manage(self.db_pool, "VerifyUserData", "get", user_qq_id=user_qq_id)
        if user_check["success"] and user_check["data"]:
            existing_user = user_check["data"]
            logger.info(f"[LinkAmongUs] 用户 {user_qq_id} 已绑定 Among Us 账号，拒绝创建验证请求。")
            return event.plain_result(f"创建验证请求失败，你的账号已绑定 {existing_user['UserFriendCode']}。\n若要解绑当前账号，请联系管理员。")

        # 检查好友代码是否已存在
        friend_code_check = await database_manage(self.db_pool, "VerifyUserData", "get")
        if friend_code_check["success"] and friend_code_check["data"]:
            if isinstance(friend_code_check["data"], list):
                existing_friend_codes = [item['UserFriendCode'] for item in friend_code_check["data"] if item.get('UserFriendCode') == friend_code]
            else:
                existing_friend_codes = [friend_code_check["data"].get('UserFriendCode')] if friend_code_check["data"].get('UserFriendCode') == friend_code else []
            
            if friend_code in existing_friend_codes:
                logger.info(f"[LinkAmongUs] 用户 {user_qq_id} 使用的好友代码已绑定他人账号，拒绝创建验证请求。")
                return event.plain_result("创建验证请求失败，该好友代码已绑定他人账号。\n若你的 Among Us 账号被他人冒用，请联系管理员。")

        # 校验好友代码格式
        if not friend_code_cheker(friend_code):
            logger.info("用户使用的好友代码非法，拒绝创建验证请求。")
            return event.plain_result("创建验证请求失败，此好友代码非法。")

        # 创建验证请求
        api_key = self.APIConfig_Key
        api_response = await request_verify_api(self.session, self.APIConfig_EndPoint, self.CreateVerifyConfig_ApiTimeout, api_key, "PUT", credentials=friend_code)
        if not api_response["success"]:
            return event.plain_result(f"创建验证请求失败，请求API时出现异常：{api_response['message']}。\n如果问题持续存在，请联系管理员。")

        # 写入验证日志
        verify_code = api_response["data"]["VerifyCode"]        
        log_data = {
            "Status": "Created",
            "UserQQID": user_qq_id,
            "UserFriendCode": friend_code,
            "VerifyCode": verify_code
        }
        insert_result = await database_manage(self.db_pool, "VerifyLog", "insert", log_data=log_data)
        if not insert_result["success"]:
            return event.plain_result(f"创建验证请求失败，写入数据库时发生意外错误：{insert_result['message']}。\n如果问题持续存在，请联系管理员。")

        process_duration = self.CreateVerifyConfig_ProcessDuration
        logger.info(f"[LinkAmongUs] 用户 {user_qq_id} 成功创建验证请求。")
        yield event.plain_result(f"成功创建验证请求，请在 {process_duration} 秒内使用账号 {friend_code} 加入 {self.APIConfig_ServerName} 房间 {verify_code} 以完成验证。")

        # 启动超时检查任务
        umo = event.unified_msg_origin
        user_group_id = event.get_group_id()
        target_is_group = user_group_id is not None
        asyncio.create_task(verification_timeout_checker(self.db_pool, self.context, user_qq_id, target_is_group, process_duration, umo, self.CreateVerifyConfig_TimeoutReminder))

    @filter.platform_adapter_type(filter.PlatformAdapterType.AIOCQHTTP)
    @verify.command("finish")
    async def verify_finish(self, event: AstrMessageEvent):
        """完成一个验证请求"""
        if not await self.whitelist_check(event):
            return
            
        user_qq_id = event.get_sender_id()
        # 检查用户是否有活跃的验证请求
        verify_log_result = await database_manage(self.db_pool, "VerifyLog", "get", latest=True, user_qq_id=user_qq_id)
        verify_log = verify_log_result["data"] if verify_log_result["success"] and verify_log_result["data"] else None
        if not verify_log:
            logger.debug(f"[LinkAmongUs] 用户 {user_qq_id} 没有活跃的验证请求，拒绝完成验证请求。")
            yield event.plain_result("你没有正在进行中的验证请求需要完成。")
            return

        logger.info(f"[LinkAmongUs] 用户 {user_qq_id} 请求完成验证。")
        # 查询验证状态
        api_key = self.APIConfig_Key
        api_response = await request_verify_api(self.session, self.APIConfig_EndPoint, self.CreateVerifyConfig_ApiTimeout, api_key, "GET", verify_log["VerifyCode"]
        )
        if not api_response["success"]:
            yield event.plain_result(f"检查验证状态失败，请求API时出现异常：{api_response['message']}。\n请重试完成验证，如果问题持续存在，请联系管理员。")
            return
        verify_status = api_response["data"].get("VerifyStatus")
        
        # 根据API返回的状态处理
        if verify_status == "NotVerified":
            await database_manage(self.db_pool, "VerifyLog", "update", sql_id=verify_log["SQLID"], status="Retrying")
            logger.info(f"[LinkAmongUs] 用户 {user_qq_id} 尚未进行验证，拒绝完成验证请求。")
            yield event.plain_result("验证失败，你还没有进行验证。")
            return
        elif verify_status == "HttpPending":
            await database_manage(self.db_pool, "VerifyLog", "update", sql_id=verify_log["SQLID"], status="Retrying")
            logger.info(f"[LinkAmongUs] 用户 {user_qq_id} 尚未完成验证，拒绝完成验证请求。")
            yield event.plain_result("验证失败，请加入房间而不是仅搜索。")
            return
        elif verify_status == "Verified":
            # 额外检查用户是否已关联账号
            user_check = await database_manage(self.db_pool, "VerifyUserData", "get", user_qq_id=user_qq_id)
            existing_user = user_check["data"] if user_check["success"] and user_check["data"] else None
            friend_code_check = await database_manage(self.db_pool, "VerifyUserData", "get")
            existing_friend_code = None
            if friend_code_check["success"] and friend_code_check["data"]:
                target_friend_code = api_response.get("FriendCode")
                if isinstance(friend_code_check["data"], list):
                    for item in friend_code_check["data"]:
                        if item.get('UserFriendCode') == target_friend_code:
                            existing_friend_code = item
                            break
                else:
                    if friend_code_check["data"].get('UserFriendCode') == target_friend_code:
                        existing_friend_code = friend_code_check["data"]
            if existing_user or existing_friend_code:
                await self.api_verify_request("DELETE", api_key, verify_code=verify_log["VerifyCode"])
                await database_manage(self.db_pool, "VerifyLog", "update", sql_id=verify_log["SQLID"], status="Cancelled")
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
            
            insert_result = await database_manage(self.db_pool, "VerifyUserData", "insert", user_data=user_data)
            if insert_result["success"]:
                await self.api_verify_request("DELETE", api_key, verify_code=verify_log["VerifyCode"])
                await database_manage(self.db_pool, "VerifyLog", "update", sql_id=verify_log["SQLID"], status="Verified")
                success_message = (
                    f"验证成功！已将 {user_data['UserAmongUsName']}({user_data['UserFriendCode']}) 关联 QQ {user_data['UserQQID']}。"
                )
                logger.info(f"[LinkAmongUs] 成功将用户 {user_qq_id} 关联好友代码 {user_data['UserFriendCode']}。")
                yield event.send_message(success_message)
            else:
                logger.error(f"[LinkAmongUs] 用户 {user_qq_id} 验证数据写入失败。")
                yield event.plain_result(f"验证失败，数据库写入异常：{insert_result['message']}。\n请重试完成验证，如果问题持续存在，请联系管理员。")
        elif verify_status == "Expired":
            await database_manage(self.db_pool, "VerifyLog", "update", sql_id=verify_log["SQLID"], status="Expired")
            logger.info(f"[LinkAmongUs] 用户 {user_qq_id} 验证请求已过期，拒绝完成验证请求。")
            yield event.plain_result("验证失败，你的验证请求已过期，请重新创建验证请求。")
        else:
            logger.warning(f"[LinkAmongUs] 用户 {user_qq_id} 验证请求状态 ({verify_status}) 非法，拒绝完成验证请求。")
            logger.warning("[LinkAmongUs] 这可能是插件未适配造成的，请考虑更新插件版本或联系清风适配。")
            yield event.plain_result(f"验证失败，你的验证请求状态非法。\n请重试完成验证，如问题持续存在，请联系管理员。")

        # 自动解除入群验证禁言
        logger.info(f"[LinkAmongUs] 正在尝试自动解除用户 {user_qq_id} 的入群验证禁言。")
        try:
            # 查询需要解除禁言的入群验证
            get_result = await database_manage(self.db_pool, "VerifyGroupLog", "get", user_qq_id=user_qq_id, status="Banned")
                
            if not get_result["success"]:
                logger.error(f"[LinkAmongUs] 查询入群验证禁言状态时发生错误: {get_result['message']}")
                return
                
            if not get_result["data"]:
                logger.info(f"[LinkAmongUs] 未找到用户 {user_qq_id} 进行中的入群验证，跳过自动完成入群验证。")
                return

            # 确保banned_logs是列表格式
            banned_logs = get_result["data"] if isinstance(get_result["data"], list) else [get_result["data"]]
            unbanned_groups = []
            
            for log in banned_logs:
                log_id = log["SQLID"]
                group_id = log["BanGroupID"]
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
                    
                    # 更新验证日志状态为已解除禁言
                    update_result = await database_manage(self.db_pool, "VerifyGroupLog", "update", 
                        sql_id=log_id, status="Unbanned")
                    if not update_result["success"]:
                        logger.error(f"[LinkAmongUs] 更新入群验证状态时发生意外错误: {update_result['message']}。")
                        
                except Exception as e:
                    logger.error(f"[LinkAmongUs] 解除用户 {user_qq_id} 在群 {group_id} 的禁言时发生意外错误: {e}")
                    
            yield event.plain_result("已尝试自动解除你的入群验证禁言，如不生效请联系群聊管理员手动解除。")
            
        except Exception as e:
            logger.error(f"[LinkAmongUs] 处理用户 {user_qq_id} 入群验证禁言时发生意外错误: {e}")
            yield event.plain_result("尝试自动处理入群验证禁言时发生意外错误，请联系管理员。")          

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
            get_result = await database_manage(self.db_pool, "VerifyLog", "get", 
                status=["Created", "Retrying"],  # 使用列表表示IN条件
                sql_id=None, verify_code=None, user_qq_id=None, user_friend_code=None, create_time=None, status_not=None  # 添加必需的字段
            )
            if not get_result["success"]:
                logger.error(f"[LinkAmongUs] 查询验证记录失败: {get_result['message']}")
                yield event.plain_result("查询失败，发生意外错误，请查看日志。")
                return
            
            if not get_result["data"]:
                logger.info("[LinkAmongUs] 未找到非法验证状态请求。")
                yield event.plain_result("没有找到需要清理的验证请求。")
                return
                
            # 确保results是列表格式
            results = get_result["data"] if isinstance(get_result["data"], list) else [get_result["data"]]
            expired_count = 0
            logger.debug(f"[LinkAmongUs] 已找到 {len(results)} 条待检查的验证请求。")

            # 检查每条记录是否超时
            for record in results:
                create_time = record["CreateTime"]
                time_diff = (current_time - create_time).total_seconds()
                if time_diff > process_duration:
                    update_result = await database_manage(self.db_pool, "VerifyLog", "update", sql_id=record["SQLID"], status="Expired")
                    if update_result["success"]:
                        expired_count += 1
                        logger.debug(f"[LinkAmongUs] 验证请求 ID {record['SQLID']} 已过期，正在处理。")
                    else:
                        logger.error(f"[LinkAmongUs] 更新验证记录失败: {update_result['message']}")
                    
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
        
        # 先尝试按QQ号查询
        get_result = await database_manage(self.db_pool, "VerifyUserData", "get", user_qq_id=query_value)
        if not get_result["success"] or not get_result["data"]:
            # 如果按QQ号没找到，再尝试按好友代码查询
            get_result = await database_manage(self.db_pool, "VerifyUserData", "get", user_friend_code=query_value)
        
        if get_result["success"] and get_result["data"]:
            user_data = get_result["data"]
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
        verify_log_result = await database_manage(self.db_pool, "VerifyLog", "get", latest=True, user_qq_id=user_qq_id)
        verify_log = verify_log_result["data"] if verify_log_result["success"] and verify_log_result["data"] else None
        if not verify_log:
            logger.debug(f"[LinkAmongUs] 用户 {user_qq_id} 没有活跃的验证请求，拒绝取消验证请求。")
            yield event.plain_result("你没有进行中的验证请求需要取消。")
            return

        logger.info(f"[LinkAmongUs] 用户 {user_qq_id} 请求取消验证请求。")
        api_key = self.APIConfig_Key
        verify_code = verify_log["VerifyCode"]
        delete_result = await request_verify_api(self.session, self.APIConfig_EndPoint, self.CreateVerifyConfig_ApiTimeout, "DELETE", api_key, verify_code)
        delete_success = delete_result["success"]
        update_result = await database_manage(self.db_pool, "VerifyLog", "update", sql_id=verify_log["SQLID"], status="Cancelled")
        update_success = update_result["success"]
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
        
        get_result = await database_manage(self.db_pool, "VerifyUserData", "get", user_qq_id=user_qq_id)
        if get_result["success"] and get_result["data"]:
            user_data = get_result["data"]
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

        user_check_result = await database_manage(self.db_pool, "VerifyUserData", "get", user_qq_id=user_qq_id)
        user_data = user_check_result["data"] if user_check_result["success"] and user_check_result["data"] else None
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
            
            # 写入验证日志
            log_data = {
                "Status": "Created",
                "VerifyUserID": user_qq_id,
                "BanGroupID": group_id,
                "KickTime": kick_time
            }
            insert_result = await database_manage(self.db_pool, "VerifyGroupLog", "insert", **log_data)
            if not insert_result["success"]:
                logger.error(f"[LinkAmongUs] 写入验证日志失败: {insert_result['message']}")
                return
            log_id = insert_result["data"]  # 返回的是新插入记录的ID

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
            # 更新验证日志状态
            update_result = await database_manage(self.db_pool, "VerifyGroupLog", "update", 
                sql_id=log_id, 
                Status="Banned"
            )
            if not update_result["success"]:
                logger.error(f"[LinkAmongUs] 更新验证日志状态失败: {update_result['message']}")
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
        if raw_message.get("notice_type") != "group_decrease":
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
            # 查找验证日志
            log_result = await database_manage(self.db_pool, "VerifyGroupLog", "get", 
                VerifyUserID=user_qq_id, BanGroupID=group_id)
            if not log_result["success"] or not log_result["data"]:
                logger.debug(f"[LinkAmongUs] 未找到用户 {user_qq_id} 在群 {group_id} 的验证日志。")
                return
                
            # 取消入群验证
            log_data = log_result["data"]
            log_id = log_data["SQLID"]
            status = log_data["Status"]
            if status in ["Created", "Banned"]:
                update_result = await database_manage(self.db_pool, "VerifyGroupLog", "update", 
                    sql_id=log_id, 
                    Status="Cancelled"
                )
                if update_result["success"]:
                    logger.info(f"[LinkAmongUs] 已取消成员 {user_qq_id} 在群 {group_id} 的入群验证。")
                else:
                    logger.error(f"[LinkAmongUs] 取消验证失败: {update_result['message']}")
                        
        except Exception as e:
            logger.error(f"[LinkAmongUs] 处理用户 {user_qq_id} 退群 {group_id} 事件时发生错误: {e}")

    async def group_ban_lift_ban(self, event: AstrMessageEvent):
        """防止入群验证成员被解除禁言"""
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
        if raw_message.get("notice_type") != "group_ban":
            return
        if raw_message.get("sub_type") != "lift_ban":
            return
        if not await self.whitelist_check(event):
            return

        pass

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
                get_result = await database_manage(self.db_pool, "VerifyGroupLog", "get", 
                    Status="Banned", 
                    KickTime=f"<={current_time}",  # 使用字符串表示条件
                    sql_id=None, VerifyUserID=None, BanGroupID=None  # 添加必需的字段
                )
                
                # 检查结果并处理
                if not get_result["success"]:
                    logger.error(f"[LinkAmongUs] 查询需要踢出的成员失败: {get_result['message']}")
                elif not get_result["data"]:
                    logger.debug("[LinkAmongUs] 没有需要踢出的未验证成员。")
                else:
                    # 确保 users_to_kick 是列表格式
                    users_to_kick = get_result["data"] if isinstance(get_result["data"], list) else [get_result["data"]]
                    logger.debug(f"[LinkAmongUs] 已找到 {len(users_to_kick)} 个需要踢出的未验证成员。")

                    # 踢出用户
                    for user in users_to_kick:
                        log_id = user["SQLID"]
                        user_qq_id = user["VerifyUserID"]
                        group_id = user["BanGroupID"]
                        
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
                            update_result = await database_manage(self.db_pool, "VerifyGroupLog", "update", 
                                sql_id=log_id, 
                                Status="Kicked"
                            )
                            if update_result["success"]:
                                logger.info(f"[LinkAmongUs] 已在群 {group_id} 踢出用户 {user_qq_id}。")
                            else:
                                logger.error(f"[LinkAmongUs] 更新验证日志失败: {update_result['message']}")
                            
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