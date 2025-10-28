import asyncio
import aiohttp
import aiomysql
import json
from typing import Optional, Dict, Any
from datetime import datetime

from astrbot.api.event import filter, AstrMessageEvent, MessageEventResult
from astrbot.api.star import Context, Star, register
from astrbot.api import logger

class LinkAmongUsPlugin(Star):
    def __init__(self, context: Context):
        super().__init__(context)
        self.db_pool = None
        self.session = None
        self.config = {}
        
    async def initialize(self):
        """初始化插件，建立数据库连接池和HTTP会话"""
        try:
            # 获取配置
            self.config = self.context.get_config()
            
            # 创建数据库连接池
            mysql_config = self.config.get("MySQLConfig", {})
            self.db_pool = await aiomysql.create_pool(
                host=mysql_config.get("MySQLConfig_Address", "127.0.0.1"),
                port=mysql_config.get("MySQLConfig_Port", 3306),
                user=mysql_config.get("MySQLConfig_User", "root"),
                password=mysql_config.get("MySQLConfig_Password", ""),
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

    async def check_whitelist_group(self, group_id: str) -> bool:
        """检查群组是否在白名单中"""
        white_list = self.get_config_value("VerifyConfig.VerifyConfig_WhiteGroup", [])
        # 如果白名单为空，则在所有群组中启用
        if not white_list:
            return True
        return group_id in white_list

    @filter.command("verify create")
    async def verify_create(self, event: AstrMessageEvent):
        """创建验证请求命令"""
        # 检查是否在白名单群组中
        group_id = event.get_group_id()
        if group_id and not await self.check_whitelist_group(group_id):
            yield event.plain_result("此群组不在验证服务白名单中。")
            return

        # 获取用户输入的好友代码
        message_parts = event.message_str.strip().split()
        if len(message_parts) < 3:
            yield event.plain_result("参数错误，请使用格式: /verify create <好友代码>")
            return
            
        friend_code = message_parts[2]
        user_qq_id = event.get_sender_id()
        user_qq_name = event.get_sender_name()

        # 检查好友代码是否在黑名单中
        if await self.check_black_friend_code(friend_code):
            yield event.plain_result("创建验证请求失败，此好友代码不能用于创建验证请求。")
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
