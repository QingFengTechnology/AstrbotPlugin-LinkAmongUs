import asyncio
import aiohttp
import aiomysql
from typing import Optional, Dict, Any
from datetime import datetime

from astrbot.api.event import filter, AstrMessageEvent
from astrbot.api.star import Context, Star
from astrbot.api import logger
from astrbot.api import AstrBotConfig

class LinkAmongUsPlugin(Star):
    def __init__(self, context: Context, config: AstrBotConfig = None):
        super().__init__(context)
        self.db_pool = None
        self.session = None
        self.config = config if config is not None else {}
        
        # 加载白名单群组配置
        self.whitelist_groups = self.get_config_value("WhitelistGroups", [])
        logger.debug("[LinkAmongUs] 插件已启动。")
        
    async def initialize(self):
        """初始化插件，建立数据库连接池和HTTP会话"""
        try:
            # 创建数据库连接池
            mysql_config = self.config.get("MySQLConfig", {})
            mysql_host = mysql_config.get("MySQLConfig_Address")
            logger.debug(f"[LinkAmongUs] 尝试连接到MySQL服务器: {mysql_host}:{mysql_config.get('MySQLConfig_Port', 3306)}")
                
            self.db_pool = await aiomysql.create_pool(
                host=mysql_host,
                port=mysql_config.get("MySQLConfig_Port", 3306),
                user=mysql_config.get("MySQLConfig_UserName", "LinkAmongUs"),
                password=mysql_config.get("MySQLConfig_UserPassword", ""),
                db=mysql_config.get("MySQLConfig_Database", "LinkAmongUs"),
                charset='utf8mb4',
                autocommit=True
            )
            
            # 创建HTTP会话
            self.session = aiohttp.ClientSession()
            
            logger.info("[LinkAmongUs] 插件初始化完成。")
        except Exception as e:
            logger.error(f"[LinkAmongUs] 初始化时发生错误: {e}")
            raise

    async def terminate(self):
        """插件销毁时关闭数据库连接和HTTP会话"""
        if self.db_pool:
            self.db_pool.close()
            await self.db_pool.wait_closed()
        if self.session:
            await self.session.close()
        logger.debug("[LinkAmongUs] 插件已停止。")

    def get_config_value(self, key_path: str, default=None):
        """获取配置值"""
        keys = key_path.split('.')
        value = self.config
        try:
            for key in keys:
                value = value[key]
            return value
        except KeyError:
            return default

    async def check_black_friend_code(self, friend_code: str) -> bool:
        """检查好友代码是否在黑名单中"""
        black_list = self.get_config_value("VerifyConfig.VerifyConfig_BlackFriendCode", [])
        return friend_code in black_list

    async def check_user_exists_in_verify_data(self, user_qq_id: str) -> Optional[Dict[str, Any]]:
        """检查用户QQ号是否已存在于VerifyUserData表中"""
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
        """检查好友代码是否已存在于VerifyUserData表中"""
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

    async def create_verify_request(self, api_key: str, friend_code: str) -> Optional[Dict[str, Any]]:
        """向API发送PUT请求创建验证请求"""
        api_endpoint = self.get_config_value("APIConfig.APIConfig_EndPoint", "")
        if not api_endpoint:
            logger.error("[LinkAmongUs] 未获取到有效的 API 端点，请检查你是否已在设置中配置。")
            return None
        url = f"{api_endpoint}/api/verify"
        payload = {
            "ApiKey": api_key,
            "FriendCode": friend_code
        }
        logger.info(f"[LinkAmongUs] 将以 {friend_code} 身份向 API 发送创建验证请求。")
        try:
            timeout = self.get_config_value("VerifyConfig.VerifyConfig_CreateVerfiyConfig.CreateVerfiyConfig_ApiTimeout", 6)
            async with self.session.put(url, json=payload, timeout=timeout) as response:
                if response.status == 200:
                    data = await response.json()
                    # 检查必要的字段是否存在
                    required_fields = ["VerifyStatus", "VerifyCode", "FriendCode", "ExpiresAt"]
                    if all(field in data for field in required_fields):
                        logger.info(f"[LinkAmongUs] 成功创建验证请求，验证码: {data['VerifyCode']}。")
                        return data
                    else:
                        logger.error(f"[LinkAmongUs] API 响应似乎不正确: {data}")
                else:
                    logger.error(f"[LinkAmongUs] API 请求失败，状态码: {response.status}。")
                return None
        except Exception as e:
            logger.error(f"[LinkAmongUs] 创建验证请求时发生错误: {e}")
            return None

    async def insert_verify_log(self, user_qq_id: str, friend_code: str, verify_code: str) -> bool:
        """向VerifyLog表插入验证日志"""
        logger.info(f"正在写入用户 {user_qq_id} 的验证日志。")
        if not self.db_pool:
            logger.error("[LinkAmongUs] 未能写入验证日志：数据库连接池未初始化。")
            return False
        try:
            async with self.db_pool.acquire() as conn:
                async with conn.cursor() as cursor:
                    await cursor.execute(
                        "INSERT INTO VerifyLog (Status, UserQQID, UserFriendCode, VerifyCode) VALUES (%s, %s, %s, %s)",
                        ("Created", user_qq_id, friend_code, verify_code)
                    )
                    logger.info(f"[LinkAmongUs] 成功写入用户 {user_qq_id} 的验证日志。")
                    return True
        except Exception as e:
            logger.error(f"[LinkAmongUs] 写入验证日志时发生错误: {e}")
            return False

    async def get_latest_verify_request(self, user_qq_id: str) -> Optional[Dict[str, Any]]:
        """获取用户最新的验证请求"""
        logger.info(f"[LinkAmongUs] 正在获取用户 {user_qq_id} 最新的验证请求。")
        if not self.db_pool:
            logger.error("[LinkAmongUs] 未能获取验证请求：数据库连接池未初始化。")
            return None
        async with self.db_pool.acquire() as conn:
            async with conn.cursor() as cursor:
                await cursor.execute(
                    "SELECT * FROM VerifyLog WHERE UserQQID = %s ORDER BY CreateTime DESC LIMIT 1",
                    (user_qq_id,)
                )
                result = await cursor.fetchone()
                if result:
                    columns = [desc[0] for desc in cursor.description]
                    logger.debug(f"[LinkAmongUs] 已找到用户 {user_qq_id} 的最新验证请求。")
                    return dict(zip(columns, result))
                logger.debug(f"[LinkAmongUs] 用户 {user_qq_id} 还未创建过验证请求。")
                return None

    async def get_active_verify_request(self, user_qq_id: str) -> Optional[list]:
        """获取用户所有进行中的验证请求（Status为Created或Retrying），按CreateTime降序排列"""
        logger.info(f"[LinkAmongUs] 正在获取用户 {user_qq_id} 所有进行中的验证请求。")
        if not self.db_pool:
            logger.error("[LinkAmongUs] 未能获取活跃验证请求：数据库连接池未初始化。")
            return None
        async with self.db_pool.acquire() as conn:
            async with conn.cursor() as cursor:
                await cursor.execute(
                    "SELECT * FROM VerifyLog WHERE UserQQID = %s AND Status IN ('Created', 'Retrying') ORDER BY CreateTime DESC",
                    (user_qq_id,)
                )
                results = await cursor.fetchall()
                if results:
                    columns = [desc[0] for desc in cursor.description]
                    logger.info(f"[LinkAmongUs] 已找到用户 {user_qq_id} 的活跃验证请求。")
                    return [dict(zip(columns, row)) for row in results]
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

    async def query_verify_status(self, api_key: str, verify_code: str) -> Optional[Dict[str, Any]]:
        """向API发送GET请求查询验证状态"""
        api_endpoint = self.get_config_value("APIConfig.APIConfig_EndPoint", "")
        if not api_endpoint:
            logger.error("[LinkAmongUs] 未获取到有效的 API 端点，请检查你是否已在设置中配置。")
            return None
        logger.info(f"正在查询房间 {verify_code} 的验证状态。")
        url = f"{api_endpoint}/api/verify?apikey={api_key}&verifycode={verify_code}"
        
        try:
            timeout = self.get_config_value("VerifyConfig.VerifyConfig_CreateVerfiyConfig.CreateVerfiyConfig_ApiTimeout", 6)
            async with self.session.get(url, timeout=timeout) as response:
                if response.status == 200:
                    logger.info(f"[LinkAmongUs] 成功查询房间 {verify_code} 的验证状态。")
                    return await response.json()
                logger.error(f"[LinkAmongUs] 查询房间 {verify_code} 验证状态失败，API 返回状态码 {response.status}。")
                return None
        except Exception as e:
            logger.error(f"[LinkAmongUs] 查询验证状态时发生错误: {e}")
            return None

    async def insert_verify_user_data(self, user_data: Dict[str, Any]) -> bool:
        """向VerifyUserData表插入用户验证数据"""
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

    async def delete_verify_request(self, api_key: str, verify_code: str) -> bool:
        """向API发送DELETE请求删除验证请求"""
        logger.debug(f"[LinkAmongUs] 准备删除房间 {verify_code} 的验证请求。")
        api_endpoint = self.get_config_value("APIConfig.APIConfig_EndPoint", "")
        if not api_endpoint:
            logger.error("[LinkAmongUs] 未获取到有效的 API 端点，请检查你是否已在设置中配置。")
            return False
            
        url = f"{api_endpoint}/api/verify"
        payload = {
            "apikey": api_key,
            "verifycode": verify_code
        }
        
        try:
            timeout = self.get_config_value("VerifyConfig.VerifyConfig_CreateVerfiyConfig.CreateVerfiyConfig_ApiTimeout", 6)
            async with self.session.delete(url, json=payload, timeout=timeout) as response:
                if response.status == 200:
                    logger.debug(f"[LinkAmongUs] 成功删除房间 {verify_code} 的验证请求。")
                else:
                    logger.warning(f"[LinkAmongUs] 验证请求删除失败，状态码: {response.status}, 验证码: {verify_code}")
                return response.status == 200
        except Exception as e:
            logger.error(f"[LinkAmongUs] 删除验证请求时发生错误: {e}")
            return False

    @filter.command("verify create")
    async def verify_create(self, event: AstrMessageEvent):
        """创建验证请求命令"""
        # 检查是否在白名单群组中
        group_id = event.get_group_id()
        if self.whitelist_groups and str(group_id) not in self.whitelist_groups:
            logger.debug(f"[LinkAmongUs] 群 {group_id} 不在白名单内，取消该任务。")
            return

        # 获取用户输入的好友代码
        message_parts = event.message_str.strip().split()
        if len(message_parts) < 3:
            logger.debug(f"[LinkAmongUs] 用户输入参数不正确，取消创建验证请求。")
            yield event.plain_result("参数错误，请使用格式: /verify create <好友代码>")
            return
            
        friend_code = message_parts[2]
        user_qq_id = event.get_sender_id()

        # 校验FriendCode格式：<字母>#<4位数字>，总字符数不超过25
        if len(friend_code) > 25:
            logger.debug(f"[LinkAmongUs] 用户使用的好友代码长度超过限制，拒绝使用此好友代码创建验证请求。")
            yield event.plain_result("创建验证请求失败，此好友代码非法。")
            return
            
        # 检查格式是否符合 <字母>#<4位数字>
        import re
        pattern = r'^[A-Za-z]#\d{4}$'
        if not re.match(pattern, friend_code):
            logger.debug(f"[LinkAmongUs] 用户使用的好友代码格式错误，拒绝使用此好友代码创建验证请求。")
            yield event.plain_result("创建验证请求失败，此好友代码非法。")
            return

        # 检查好友代码是否在黑名单中
        if await self.check_black_friend_code(friend_code):
            logger.debug(f"[LinkAmongUs] 用户使用的好友代码命中黑名单，拒绝使用此好友代码创建验证请求。")
            yield event.plain_result("创建验证请求失败，此好友代码非法。")
            return

        # 检查用户QQ号是否已存在于数据库中
        existing_user = await self.check_user_exists_in_verify_data(user_qq_id)
        if existing_user:
            logger.debug(f"[LinkAmongUs] 用户 {user_qq_id} 已绑定 Among Us 账号 {existing_user['UserFriendCode']}，拒绝创建验证请求。")
            yield event.plain_result(
                f"创建验证请求失败，你的账号已绑定 {existing_user['UserFriendCode']}。\n"
                f"若要更换，请联系管理员。"
            )
            return

        # 检查好友代码是否已存在于数据库中
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
            # 根据CreateTime判断最新数据
            latest_request = active_verify_request[0]  # 已经按CreateTime DESC排序，第一个就是最新的
            status = latest_request["Status"]
            create_time = latest_request["CreateTime"]
            verify_code = latest_request["VerifyCode"]
            friend_code = latest_request["FriendCode"]
            
            if status in ["Created", "Retrying"]:
                server_name = self.get_config_value("APIConfig.APIConfig_ServerName")
                logger.warning(f"[LinkAmongUs] 用户 {user_qq_id} 已有进行中的验证请求，拒绝重复创建验证请求。")
                yield event.plain_result(
                    f"创建验证请求失败，你已于 {create_time} 使用 {friend_code} 创建了一个验证请求，需要加入服务器 {server_name} 房间 {verify_code} 以完成验证。\n"
                    f"请先完成当前验证。"
                )
                return
        logger.info(f"[LinkAmongUs] 用户 {user_qq_id} 使用 Among Us 账号 {friend_code} 创建了一个验证请求。")
        # 向API发送PUT请求创建验证请求
        api_key = self.get_config_value("APIConfig.APIConfig_Key", "")
        if not api_key:
            logger.warning("[LinkAmongUs] 创建验证请求失败，未获取到 API 密钥。")
            yield event.plain_result("创建验证请求失败，API密钥未配置，请联系管理员。")
            return

        api_response = await self.create_verify_request(api_key, friend_code)
        if not api_response:
            logger.warning("[LinkAmongUs] 创建验证请求失败，API 请求失败。")
            yield event.plain_result("创建验证请求失败，请求API时出现异常，请联系管理员。")
            return

        # 向VerifyLog表插入数据
        verify_code = api_response["VerifyCode"]
        if not await self.insert_verify_log(user_qq_id, friend_code, verify_code):
            logger.warning("[LinkAmongUs] 创建验证请求失败，写入验证日志失败。")
            yield event.plain_result("创建验证请求失败，数据库写入异常，请联系管理员。")
            return

        # 发送成功消息
        process_duration = self.get_config_value("VerifyConfig.VerifyConfig_CreateVerfiyConfig.CreateVerfiyConfig_ProcessDuration", 600)
        server_name = self.get_config_value("APIConfig.APIConfig_ServerName", "服务器")
        
        success_message = (
            f"成功创建验证请求，请在 {process_duration} 秒内使用账号 {friend_code} 加入 {server_name} 房间 {verify_code} 以完成验证。"
        )
        logger.info(f"[LinkAmongUs] 用户 {user_qq_id} 成功创建验证请求。")
        yield event.plain_result(success_message)

        # 启动超时检查任务
        asyncio.create_task(self.check_verification_timeout(user_qq_id, verify_code, process_duration))

    async def check_verification_timeout(self, user_qq_id: str, verify_code: str, timeout: int):
        """检查验证是否超时"""
        logger.debug(f"[LinkAmongUs] 启动用户 {user_qq_id} 的验证超时检查。")
        await asyncio.sleep(timeout)
        
        # 重新读取验证日志数据
        verify_log = await self.get_latest_verify_request(user_qq_id)
        if verify_log and verify_log["VerifyCode"] == verify_code:
            # 检查状态是否为已完成状态
            if verify_log["Status"] not in ["Verified", "Cancelled", "Expired"]:
                # 更新状态为已过期
                logger.info(f"[LinkAmongUs] 用户 {user_qq_id} 的验证请求已超时。")
                await self.update_verify_log_status(verify_log["SQLID"], "Expired")

    @filter.command("verify check")
    async def verify_check(self, event: AstrMessageEvent):
        """检查验证状态命令"""
        # 检查是否在白名单群组中
        group_id = event.get_group_id()
        if self.whitelist_groups and str(group_id) not in self.whitelist_groups:
            logger.debug(f"[LinkAmongUs] 群 {group_id} 不在白名单内，取消该任务。")
            return
            
        user_qq_id = event.get_sender_id()
        
        # 检查用户是否有验证请求
        verify_log = await self.get_latest_verify_request(user_qq_id)
        if not verify_log:
            logger.debug(f"[LinkAmongUs] 用户 {user_qq_id} 没有验证请求，拒绝完成验证请求。")
            yield event.plain_result("你还没有创建验证请求，或是该验证请求已过期。")
            return

        # 检查验证请求状态
        if verify_log["Status"] not in ["Created", "Retrying"]:
            logger.warning(f"[LinkAmongUs] 用户 {user_qq_id} 验证请求已失效，拒绝完成验证请求。")
            yield event.plain_result("你的验证请求已失效，请重新创建验证请求。")
            return

        logger.info(f"[LinkAmongUs] 用户 {user_qq_id} 请求完成验证。")

        # 向API发送GET请求查询验证状态
        api_key = self.get_config_value("APIConfig.APIConfig_Key", "")
        if not api_key:
            logger.warning("[LinkAmongUs] 完成验证请求失败，未获取到 API 密钥。")
            yield event.plain_result("检查验证失败，API密钥未配置，请联系管理员。")
            return

        api_response = await self.query_verify_status(api_key, verify_log["VerifyCode"])
        if not api_response:
            logger.warning("[LinkAmongUs] 完成验证请求失败，API 请求失败。")
            yield event.plain_result("检查验证失败，请求API时出现异常，请联系管理员。")
            return

        verify_status = api_response.get("VerifyStatus", "")
        logger.debug(f"[LinkAmongUs] 已查询到用户 {user_qq_id} 的验证状态：{verify_status}。")
        
        # 根据API返回的状态处理
        if verify_status == "NotVerified":
            await self.update_verify_log_status(verify_log["SQLID"], "Retrying")
            logger.info(f"[LinkAmongUs] 用户 {user_qq_id} 的验证请求为未完成，拒绝完成验证请求。")
            yield event.plain_result("验证失败，你还没有进行验证。")
        elif verify_status == "HttpPending":
            await self.update_verify_log_status(verify_log["SQLID"], "Retrying")
            logger.info(f"[LinkAmongUs] 用户 {user_qq_id} 的验证请求正等待 API 服务器处理完成，拒绝完成验证请求。")
            yield event.plain_result("验证失败，请等待服务端处理完成。\n请稍后重试提交验证。")
        elif verify_status == "Verified":
            # 额外检查用户的QQ号和FriendCode是否已存在于数据库
            existing_user = await self.check_user_exists_in_verify_data(user_qq_id)
            existing_friend_code = await self.check_friend_code_exists_in_verify_data(api_response.get("FriendCode", ""))
            
            # 如果用户QQ号或FriendCode已存在，则标记为Cancelled并提示用户
            if existing_user or existing_friend_code:
                await self.delete_verify_request(api_key, verify_log["VerifyCode"])
                # 更新验证日志状态为Cancelled
                await self.update_verify_log_status(verify_log["SQLID"], "Cancelled")
                
                # 构建错误消息
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
            
            # 插入用户验证数据
            user_data = {
                "UserQQName": event.get_sender_name(),
                "UserQQID": user_qq_id,
                "UserAmongUsName": api_response.get("PlayerName", ""),
                "UserFriendCode": api_response.get("FriendCode", ""),
                "UserPuid": api_response.get("Puid", ""),
                "UserHashedPuid": api_response.get("HashedPuid", ""),
                "UserUdpPlatform": api_response.get("UdpPlatform", ""),
                "UserTokenPlatform": api_response.get("TokenPlatform", ""),
                "UserUdpIP": api_response.get("UdpIp", ""),
                "UserHttpIP": api_response.get("HttpIp", "")
            }
            
            if await self.insert_verify_user_data(user_data):
                # 向API发送DELETE请求删除验证请求
                await self.delete_verify_request(api_key, verify_log["VerifyCode"])
                
                # 更新验证日志状态
                await self.update_verify_log_status(verify_log["SQLID"], "Verified")
                
                # 发送成功消息
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

    @filter.permission_type(filter.PermissionType.ADMIN)
    @filter.command("verify clean")
    async def verify_clean(self, event: AstrMessageEvent):
        """清理过期验证请求命令（仅管理员可用）"""
        # 获取超时时间配置
        process_duration = self.get_config_value("VerifyConfig.VerifyConfig_CreateVerfiyConfig.CreateVerfiyConfig_ProcessDuration", 600)
        logger.info(f"[LinkAmongUs] 管理员请求了清理数据库中的非法验证请求。")
        
        if not self.db_pool:
            logger.error("[LinkAmongUs] 清理数据库非法验证请求失败：数据库连接池未初始化。")
            yield event.plain_result("清理失败，数据库连接池未初始化。")
            return

        try:
            # 获取当前时间
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
                        
                        # 计算时间差（秒）
                        time_diff = (current_time - create_time).total_seconds()
                        
                        # 如果超时，更新状态为Expired
                        if time_diff > process_duration:
                            await self.update_verify_log_status(record["SQLID"], "Expired")
                            expired_count += 1
                            logger.debug(f"[LinkAmongUs] 验证请求 ID {record['SQLID']} 已过期，正在处理。")
                    
                    # 发送结果报告
                    logger.info(f"[LinkAmongUs] 清理非法验证请求完成，共处理 {len(results)} 条验证请求，其中 {expired_count} 条非法，已进行处理。")
                    yield event.plain_result(f"清理完成，共处理 {len(results)} 条验证请求，其中 {expired_count} 条非法。")
                    
        except Exception as e:
            logger.error(f"[LinkAmongUs] 清理非法验证请求时发生错误: {e}")
            yield event.plain_result("清理失败，发生意外错误，请查看日志。")

    @filter.command("verify help")
    async def verify_help(self, event: AstrMessageEvent):
        """帮助命令"""
        # 检查是否在白名单群组中
        group_id = event.get_group_id()
        if self.whitelist_groups and str(group_id) not in self.whitelist_groups:
            logger.debug(f"[LinkAmongUs] 群 {group_id} 不在白名单内，取消该任务。")
            return
            
        # 从配置中获取帮助文本
        help_text = self.get_config_value("HelpConfig.HelpConfig_Text", "")
        
        # 如果配置为空，则不启用该命令
        if not help_text:
            logger.debug("[LinkAmongUs] 帮助文本未配置，取消显示帮助文本。")
            return
            
        logger.debug(f"[LinkAmongUs] 将发送帮助信息至群里 {group_id}。")
        yield event.plain_result(help_text)
