import asyncio
import aiohttp
import aiomysql
import json
from typing import Optional, Dict, Any
from datetime import datetime

from astrbot.api.event import filter, AstrMessageEvent, MessageEventResult
from astrbot.api.star import Context, Star, register
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
        
    async def initialize(self):
        """初始化插件，建立数据库连接池和HTTP会话"""
        try:
            # 创建数据库连接池
            mysql_config = self.config.get("MySQLConfig", {})
            # 确保使用配置中的MySQL地址，如果没有则抛出错误
            mysql_host = mysql_config.get("MySQLConfig_Address")
            if not mysql_host:
                raise ValueError("MySQLConfig_Address 未在配置中设置")
                
            logger.info(f"尝试连接到MySQL服务器: {mysql_host}:{mysql_config.get('MySQLConfig_Port', 3306)}")
                
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
            
            logger.info("LinkAmongUs插件初始化成功")
        except Exception as e:
            logger.error(f"LinkAmongUs插件初始化失败: {e}")
            raise

    async def terminate(self):
        """插件销毁时关闭数据库连接和HTTP会话"""
        if self.db_pool:
            self.db_pool.close()
            await self.db_pool.wait_closed()
        if self.session:
            await self.session.close()
        logger.info("LinkAmongUs插件已关闭")

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
        if not self.db_pool:
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
                    return dict(zip(columns, result))
                return None

    async def check_friend_code_exists_in_verify_data(self, friend_code: str) -> Optional[Dict[str, Any]]:
        """检查好友代码是否已存在于VerifyUserData表中"""
        if not self.db_pool:
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
                    return dict(zip(columns, result))
                return None

    async def create_verify_request(self, api_key: str, friend_code: str) -> Optional[Dict[str, Any]]:
        """向API发送PUT请求创建验证请求"""
        api_endpoint = self.get_config_value("APIConfig.APIConfig_EndPoint", "")
        if not api_endpoint:
            return None
            
        url = f"{api_endpoint}/api/verify"
        payload = {
            "ApiKey": api_key,
            "FriendCode": friend_code
        }
        
        try:
            timeout = self.get_config_value("VerifyConfig.VerifyConfig_CreateVerfiyConfig.CreateVerfiyConfig_ApiTimeout", 6)
            async with self.session.put(url, json=payload, timeout=timeout) as response:
                if response.status == 200:
                    data = await response.json()
                    # 检查必要的字段是否存在
                    required_fields = ["VerifyStatus", "VerifyCode", "FriendCode", "ExpiresAt"]
                    if all(field in data for field in required_fields):
                        return data
                return None
        except Exception as e:
            logger.error(f"创建验证请求时发生错误: {e}")
            return None

    async def insert_verify_log(self, user_qq_id: str, friend_code: str, verify_code: str) -> bool:
        """向VerifyLog表插入验证日志"""
        if not self.db_pool:
            return False
            
        try:
            async with self.db_pool.acquire() as conn:
                async with conn.cursor() as cursor:
                    await cursor.execute(
                        "INSERT INTO VerifyLog (Status, UserQQID, UserFriendCode, VerifyCode) VALUES (%s, %s, %s, %s)",
                        ("Created", user_qq_id, friend_code, verify_code)
                    )
                    return True
        except Exception as e:
            logger.error(f"插入验证日志时发生错误: {e}")
            return False

    async def get_latest_verify_request(self, user_qq_id: str) -> Optional[Dict[str, Any]]:
        """获取用户最新的验证请求"""
        if not self.db_pool:
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
                    return dict(zip(columns, result))
                return None

    async def get_active_verify_request(self, user_qq_id: str) -> Optional[list]:
        """获取用户所有进行中的验证请求（Status为Created或Retrying），按CreateTime降序排列"""
        if not self.db_pool:
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
                    return [dict(zip(columns, row)) for row in results]
                return None

    async def update_verify_log_status(self, sql_id: int, status: str) -> bool:
        """更新验证日志状态"""
        if not self.db_pool:
            return False
            
        try:
            async with self.db_pool.acquire() as conn:
                async with conn.cursor() as cursor:
                    await cursor.execute(
                        "UPDATE VerifyLog SET Status = %s WHERE SQLID = %s",
                        (status, sql_id)
                    )
                    return True
        except Exception as e:
            logger.error(f"更新验证日志状态时发生错误: {e}")
            return False

    async def query_verify_status(self, api_key: str, verify_code: str) -> Optional[Dict[str, Any]]:
        """向API发送GET请求查询验证状态"""
        api_endpoint = self.get_config_value("APIConfig.APIConfig_EndPoint", "")
        if not api_endpoint:
            return None
            
        url = f"{api_endpoint}/api/verify?apikey={api_key}&verifycode={verify_code}"
        
        try:
            timeout = self.get_config_value("VerifyConfig.VerifyConfig_CreateVerfiyConfig.CreateVerfiyConfig_ApiTimeout", 6)
            async with self.session.get(url, timeout=timeout) as response:
                if response.status == 200:
                    return await response.json()
                return None
        except Exception as e:
            logger.error(f"查询验证状态时发生错误: {e}")
            return None

    async def insert_verify_user_data(self, user_data: Dict[str, Any]) -> bool:
        """向VerifyUserData表插入用户验证数据"""
        if not self.db_pool:
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
                    return True
        except Exception as e:
            logger.error(f"插入用户验证数据时发生错误: {e}")
            return False

    async def delete_verify_request(self, api_key: str, verify_code: str) -> bool:
        """向API发送DELETE请求删除验证请求"""
        api_endpoint = self.get_config_value("APIConfig.APIConfig_EndPoint", "")
        if not api_endpoint:
            return False
            
        url = f"{api_endpoint}/api/verify"
        payload = {
            "apikey": api_key,
            "verifycode": verify_code
        }
        
        try:
            timeout = self.get_config_value("VerifyConfig.VerifyConfig_CreateVerfiyConfig.CreateVerfiyConfig_ApiTimeout", 6)
            async with self.session.delete(url, json=payload, timeout=timeout) as response:
                return response.status == 200
        except Exception as e:
            logger.error(f"删除验证请求时发生错误: {e}")
            return False

    @filter.command("verify create")
    async def verify_create(self, event: AstrMessageEvent):
        """创建验证请求命令"""
        # 检查是否在白名单群组中
        group_id = event.get_group_id()
        if self.whitelist_groups and str(group_id) not in self.whitelist_groups:
            logger.debug(f"群 {group_id} 不在白名单内，跳过验证请求处理。")
            return

        # 获取用户输入的好友代码
        message_parts = event.message_str.strip().split()
        if len(message_parts) < 3:
            yield event.plain_result("参数错误，请使用格式: /verify create <好友代码>")
            return
            
        friend_code = message_parts[2]
        user_qq_id = event.get_sender_id()
        user_qq_name = event.get_sender_name()

        # 校验FriendCode格式：<字母>#<4位数字>，总字符数不超过25
        if len(friend_code) > 25:
            yield event.plain_result("创建验证请求失败，此好友代码非法。")
            return
            
        # 检查格式是否符合 <字母>#<4位数字>
        import re
        pattern = r'^[A-Za-z]#\d{4}$'
        if not re.match(pattern, friend_code):
            yield event.plain_result("创建验证请求失败，此好友代码非法。")
            return

        # 检查好友代码是否在黑名单中
        if await self.check_black_friend_code(friend_code):
            yield event.plain_result("创建验证请求失败，此好友代码非法。")
            return

        # 检查用户QQ号是否已存在于数据库中
        existing_user = await self.check_user_exists_in_verify_data(user_qq_id)
        if existing_user:
            yield event.plain_result(
                f"创建验证请求失败，你的账号已绑定 {existing_user['UserFriendCode']}。\n"
                f"若要更换，请联系管理员。"
            )
            return

        # 检查好友代码是否已存在于数据库中
        existing_friend_code = await self.check_friend_code_exists_in_verify_data(friend_code)
        if existing_friend_code:
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
                yield event.plain_result(
                    f"创建验证请求失败，你已于 {create_time} 使用 {friend_code} 创建了一个验证请求，需要加入服务器 {server_name} 房间 {verify_code} 以完成验证。\n"
                    f"请先完成当前验证。"
                )
                return

        # 向API发送PUT请求创建验证请求
        api_key = self.get_config_value("APIConfig.APIConfig_Key", "")
        if not api_key:
            yield event.plain_result("创建验证请求失败，API密钥未配置，请联系管理员。")
            return

        api_response = await self.create_verify_request(api_key, friend_code)
        if not api_response:
            yield event.plain_result("创建验证请求失败，请求API时出现异常，请联系管理员。")
            return

        # 向VerifyLog表插入数据
        verify_code = api_response["VerifyCode"]
        if not await self.insert_verify_log(user_qq_id, friend_code, verify_code):
            yield event.plain_result("创建验证请求失败，数据库写入异常，请联系管理员。")
            return

        # 发送成功消息
        process_duration = self.get_config_value("VerifyConfig.VerifyConfig_CreateVerfiyConfig.CreateVerfiyConfig_ProcessDuration", 600)
        server_name = self.get_config_value("APIConfig.APIConfig_ServerName", "服务器")
        
        success_message = (
            f"成功创建验证请求，请在 {process_duration} 秒内使用账号 {friend_code} 加入 {server_name} 房间 {verify_code} 以完成验证。"
        )
        yield event.plain_result(success_message)

        # 启动超时检查任务
        asyncio.create_task(self.check_verification_timeout(user_qq_id, verify_code, process_duration))

    async def check_verification_timeout(self, user_qq_id: str, verify_code: str, timeout: int):
        """检查验证是否超时"""
        await asyncio.sleep(timeout)
        
        # 重新读取验证日志数据
        verify_log = await self.get_latest_verify_request(user_qq_id)
        if verify_log and verify_log["VerifyCode"] == verify_code:
            # 检查状态是否为已完成状态
            if verify_log["Status"] not in ["Verified", "Cancelled", "Expired"]:
                # 更新状态为已过期
                await self.update_verify_log_status(verify_log["SQLID"], "Expired")

    @filter.command("verify check")
    async def verify_check(self, event: AstrMessageEvent):
        """检查验证状态命令"""
        # 检查是否在白名单群组中
        group_id = event.get_group_id()
        if self.whitelist_groups and str(group_id) not in self.whitelist_groups:
            logger.debug(f"群 {group_id} 不在白名单内，跳过验证状态检查。")
            return
            
        user_qq_id = event.get_sender_id()
        
        # 检查用户是否有验证请求
        verify_log = await self.get_latest_verify_request(user_qq_id)
        if not verify_log:
            yield event.plain_result("你还没有创建验证请求，或是该验证请求已过期。")
            return

        # 检查验证请求状态
        if verify_log["Status"] not in ["Created", "Retrying"]:
            yield event.plain_result("你的验证请求已失效，请重新创建验证请求。")
            return

        # 向API发送GET请求查询验证状态
        api_key = self.get_config_value("APIConfig.APIConfig_Key", "")
        if not api_key:
            yield event.plain_result("检查验证失败，API密钥未配置，请联系管理员。")
            return

        api_response = await self.query_verify_status(api_key, verify_log["VerifyCode"])
        if not api_response:
            yield event.plain_result("检查验证失败，请求API时出现异常，请联系管理员。")
            return

        verify_status = api_response.get("VerifyStatus", "")
        
        # 根据API返回的状态处理
        if verify_status == "NotVerified":
            await self.update_verify_log_status(verify_log["SQLID"], "Retrying")
            yield event.plain_result("验证失败，你还没有进行验证。")
        elif verify_status == "HttpPending":
            await self.update_verify_log_status(verify_log["SQLID"], "Retrying")
            yield event.plain_result("验证失败，请等待服务端处理完成。\n请稍后重试提交验证。")
        elif verify_status == "Verified":
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
                yield event.plain_result(success_message)
            else:
                yield event.plain_result("验证失败，数据库写入异常，请联系管理员。")
        elif verify_status == "Expired":
            await self.update_verify_log_status(verify_log["SQLID"], "Expired")
            yield event.plain_result("验证失败，请求已过期，请重新创建验证请求。")
        else:
            yield event.plain_result(f"验证失败，未知状态: {verify_status}")

    @filter.permission_type(filter.PermissionType.ADMIN)
    @filter.command("verify clean")
    async def verify_clean(self, event: AstrMessageEvent):
        """清理过期验证请求命令（仅管理员可用）"""
        # 获取超时时间配置
        process_duration = self.get_config_value("VerifyConfig.VerifyConfig_CreateVerfiyConfig.CreateVerfiyConfig_ProcessDuration", 600)
        
        if not self.db_pool:
            yield event.plain_result("清理失败，数据库连接未建立。")
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
                        yield event.plain_result("没有找到需要清理的验证请求。")
                        return
                    
                    expired_count = 0
                    columns = [desc[0] for desc in cursor.description]
                    
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
                    
                    # 发送结果报告
                    yield event.plain_result(f"清理完成，共处理 {len(results)} 条验证请求，其中 {expired_count} 条已超时并标记为过期。")
                    
        except Exception as e:
            logger.error(f"清理过期验证请求时发生错误: {e}")
            yield event.plain_result("清理失败，发生内部错误，请查看日志。")

    @filter.command("verify help")
    async def verify_help(self, event: AstrMessageEvent):
        """帮助命令"""
        # 检查是否在白名单群组中
        group_id = event.get_group_id()
        if self.whitelist_groups and str(group_id) not in self.whitelist_groups:
            logger.debug(f"群 {group_id} 不在白名单内，跳过帮助命令处理。")
            return
            
        # 从配置中获取帮助文本
        help_text = self.get_config_value("HelpConfig.HelpConfig_Text", "")
        
        # 如果配置为空，则不启用该命令
        if not help_text:
            return
            
        yield event.plain_result(help_text)
