import asyncio
import aiohttp
import aiomysql
from typing import Optional, Dict, Any
from datetime import datetime

from astrbot.api.event import filter, AstrMessageEvent
from astrbot.api.star import Context, Star
from astrbot.api import logger
from astrbot.api import AstrBotConfig

HELP_MENU = """AstrbotPlugin-LinkAmongUs v1.3.0 By QingFeng
/verify help - 显示此帮助菜单。

/verify create <FriendCode> - 创建一个验证请求。
Args:
  - FriendCode: 必填。你要关联的 Among Us 好友代码。

/verify finish - 完成一个验证请求。
- 由于服务器技术限制暂不支持自动完成，因此您必须要通过此命令主动完成验证请求。

/verify info - 查询您的绑定信息。
- 显示您当前绑定的 Among Us 角色名、好友代码和绑定时间。

@PermissionType.ADMIN
/verify query <QQID|FriendCode> - 查询指定用户的账号关联信息。
Args:
  - QQID|FriendCode: 必填。要查询的用户QQ号或好友代码（二选一）。

@PermissionType.ADMIN
/verfiy clean - 清理数据库中的非法验证请求。
- 此操作将检查数据库中的验证日志表，将所有创建超过 10 分钟的但仍未结束的验证日志标记为过期。
"""

class LinkAmongUs(Star):
    def __init__(self, context: Context, config: Dict[str, Any]):
        super().__init__(context)
        self.db_pool = None
        self.session = None
        self.config = config
        
        # 加载配置
        self._load_config()
        logger.debug("[LinkAmongUs] 插件已启动。")
    
    def _load_config(self):
        """加载插件配置"""
        # 加载白名单群组配置
        self.whitelist_groups = self.config.get("WhitelistGroups", [])
        
        # 加载MySQL配置
        self.mysql_config = self.config.get("MySQLConfig", {})
        
        # 加载API配置
        self.api_config = self.config.get("APIConfig", {})
        
        # 加载验证配置
        self.verify_config = self.config.get("VerifyConfig", {})
        
        # 加载帮助配置
        self.help_config = self.config.get("HelpConfig", {})
        
    async def initialize(self):
        """初始化插件"""
        try:
            # 创建数据库连接池
            mysql_host = self.mysql_config.get("MySQLConfig_Address")
            logger.debug(f"[LinkAmongUs] 尝试连接到MySQL服务器: {mysql_host}:{self.mysql_config.get('MySQLConfig_Port')}")
                
            self.db_pool = await aiomysql.create_pool(
                host=mysql_host,
                port=self.mysql_config.get("MySQLConfig_Port"),
                user=self.mysql_config.get("MySQLConfig_UserName"),
                password=self.mysql_config.get("MySQLConfig_UserPassword"),
                db=self.mysql_config.get("MySQLConfig_Database"),
                charset='utf8mb4',
                autocommit=True
            )
            
            # 检查并创建必要的数据表
            await self._check_and_create_tables()
            
            # 创建HTTP会话
            self.session = aiohttp.ClientSession()
            
            logger.info("[LinkAmongUs] 插件初始化完成。")
        except Exception as e:
            logger.error(f"[LinkAmongUs] 初始化时发生错误: {e}")
            raise

    async def _check_and_create_tables(self):
        """检查并创建必要的数据表"""
        logger.debug("[LinkAmongUs] 正在进行数据表完整性校验。")
        
        # 需要检查的数据表列表
        required_tables = ["VerifyUserData", "VerifyLog"]
        
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
                        await self._create_table(cursor, table_name)
                    else:
                        logger.debug(f"[LinkAmongUs] 数据表 {table_name} 已存在。")

    async def _create_table(self, cursor, table_name):
        """创建指定的数据表"""
        try:
            if table_name == "VerifyUserData":
                await cursor.execute("""
                    CREATE TABLE IF NOT EXISTS VerifyUserData (
                        SQLID smallint NOT NULL AUTO_INCREMENT,
                        LastUpdated datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        UserQQName varchar(40) DEFAULT NULL,
                        UserQQID varchar(13) NOT NULL,
                        UserAmongUsName varchar(11) DEFAULT NULL,
                        UserFriendCode varchar(32) NOT NULL,
                        UserPuid varchar(48) NOT NULL,
                        UserHashedPuid varchar(11) NOT NULL,
                        UserUdpPlatform varchar(32) NOT NULL,
                        UserTokenPlatform varchar(32) NOT NULL,
                        UserUdpIP varchar(32) NOT NULL,
                        UserHttpIP varchar(128) NOT NULL,
                        PRIMARY KEY (SQLID),
                        UNIQUE KEY unique_user_data (UserQQID, UserFriendCode, UserPuid, UserHashedPuid)
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci
                """)
            elif table_name == "VerifyLog":
                await cursor.execute("""
                    CREATE TABLE IF NOT EXISTS VerifyLog (
                        SQLID smallint NOT NULL AUTO_INCREMENT,
                        CreateTime datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        Status set('Created','Retrying','Verified','Cancelled','Expired') CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
                        UserQQID varchar(13) NOT NULL,
                        UserFriendCode varchar(32) NOT NULL,
                        VerifyCode varchar(7) NOT NULL,
                        PRIMARY KEY (SQLID)
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci
                """)
            
            logger.debug(f"[LinkAmongUs] 数据表 {table_name} 创建成功。")
        except Exception as e:
            logger.error(f"[LinkAmongUs] 创建数据表 {table_name} 时发生错误: {e}")
            raise

    async def terminate(self):
        """停止插件"""
        if self.db_pool:
            self.db_pool.close()
            await self.db_pool.wait_closed()
        if self.session:
            await self.session.close()
        logger.debug("[LinkAmongUs] 插件已停止。")

    async def check_black_friend_code(self, friend_code: str) -> bool:
        """检查好友代码是否在黑名单中"""
        black_list = self.verify_config.get("VerifyConfig_BlackFriendCode", [])
        return friend_code in black_list

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

    async def get_user_verify_info(self, user_qq_id: str) -> Optional[Dict[str, Any]]:
        """获取用户的绑定信息"""
        logger.info(f"[LinkAmongUs] 正在查询用户 {user_qq_id} 的绑定信息。")
        if not self.db_pool:
            logger.error("[LinkAmongUs] 未能查询用户绑定信息：数据库连接池未初始化。")
            return None
        
        async with self.db_pool.acquire() as conn:
            async with conn.cursor() as cursor:
                await cursor.execute(
                    "SELECT UserAmongUsName, UserFriendCode, LastUpdated, UserHashedPuid, UserTokenPlatform FROM VerifyUserData WHERE UserQQID = %s",
                    (user_qq_id,)
                )
                result = await cursor.fetchone()
                if result:
                    columns = [desc[0] for desc in cursor.description]
                    result_dict = dict(zip(columns, result))
                    logger.info(f"[LinkAmongUs] 成功查询到用户 {user_qq_id} 的绑定信息。")
                    return result_dict
                logger.info(f"[LinkAmongUs] 用户 {user_qq_id} 尚未绑定 Among Us 账号。")
                return None

    async def query_user_verify_info(self, identifier: str) -> Optional[Dict[str, Any]]:
        """根据UserQQID或UserFriendCode查询用户的绑定信息（管理员专用）"""
        logger.info(f"[LinkAmongUs] 管理员正在查询用户 {identifier} 的绑定信息。")
        if not self.db_pool:
            logger.error("[LinkAmongUs] 未能查询用户绑定信息：数据库连接池未初始化。")
            return None
        
        async with self.db_pool.acquire() as conn:
            async with conn.cursor() as cursor:
                # 首先尝试按UserQQID查询
                await cursor.execute(
                    "SELECT UserQQID, UserAmongUsName, UserFriendCode, LastUpdated, UserHashedPuid, UserTokenPlatform FROM VerifyUserData WHERE UserQQID = %s",
                    (identifier,)
                )
                result = await cursor.fetchone()
                
                # 如果没有找到，再尝试按UserFriendCode查询
                if not result:
                    await cursor.execute(
                        "SELECT UserQQID, UserAmongUsName, UserFriendCode, LastUpdated, UserHashedPuid, UserTokenPlatform FROM VerifyUserData WHERE UserFriendCode = %s",
                        (identifier,)
                    )
                    result = await cursor.fetchone()
                
                if result:
                    columns = [desc[0] for desc in cursor.description]
                    result_dict = dict(zip(columns, result))
                    logger.info(f"[LinkAmongUs] 管理员成功查询到用户 {identifier} 的绑定信息。")
                    return result_dict
                logger.info(f"[LinkAmongUs] 未找到用户 {identifier} 的绑定信息。")
                return None

    async def create_verify_request(self, api_key: str, friend_code: str) -> Optional[Dict[str, Any]]:
        """向 API 发送创建验证请求"""
        api_endpoint = self.api_config.get("APIConfig_EndPoint")
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
            create_verify_config = self.verify_config.get("VerifyConfig_CreateVerfiyConfig", {})
            timeout = create_verify_config.get("CreateVerfiyConfig_ApiTimeout")
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
        """写入验证日志"""
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

    async def query_verify_status(self, api_key: str, verify_code: str) -> Optional[Dict[str, Any]]:
        """向 API 查询验证请求状态"""
        api_endpoint = self.api_config.get("APIConfig_EndPoint")
        if not api_endpoint:
            logger.error("[LinkAmongUs] 未获取到有效的 API 端点，请检查你是否已在设置中配置。")
            return None
        logger.info(f"正在查询房间 {verify_code} 的验证状态。")
        url = f"{api_endpoint}/api/verify?apikey={api_key}&verifycode={verify_code}"
        
        try:
            create_verify_config = self.verify_config.get("VerifyConfig_CreateVerfiyConfig", {})
            timeout = create_verify_config.get("CreateVerfiyConfig_ApiTimeout")
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

    async def delete_verify_request(self, api_key: str, verify_code: str) -> bool:
        """向 API 删除验证请求"""
        logger.debug(f"[LinkAmongUs] 准备删除房间 {verify_code} 的验证请求。")
        api_endpoint = self.api_config.get("APIConfig_EndPoint")
        if not api_endpoint:
            logger.error("[LinkAmongUs] 未获取到有效的 API 端点，请检查你是否已在设置中配置。")
            return False
            
        url = f"{api_endpoint}/api/verify"
        payload = {
            "apikey": api_key,
            "verifycode": verify_code
        }
        
        try:
            create_verify_config = self.verify_config.get("VerifyConfig_CreateVerfiyConfig", {})
            timeout = create_verify_config.get("CreateVerfiyConfig_ApiTimeout")
            async with self.session.delete(url, json=payload, timeout=timeout) as response:
                if response.status == 200:
                    logger.debug(f"[LinkAmongUs] 成功删除房间 {verify_code} 的验证请求。")
                else:
                    logger.warning(f"[LinkAmongUs] 验证请求删除失败，状态码: {response.status}, 验证码: {verify_code}")
                return response.status == 200
        except Exception as e:
            logger.error(f"[LinkAmongUs] 删除验证请求时发生错误: {e}")
            return False

    @filter.command_group("verify")
    def verify(self):
        """插件命令列表"""
        group_id = event.get_group_id()
        if self.whitelist_groups and str(group_id) not in self.whitelist_groups:
            logger.debug(f"[LinkAmongUs] 群 {group_id} 不在白名单内，取消该任务。")
            return
        yield event.plain_result("""
        命令列表：
        /verify help - 显示帮助菜单
        /verify create - 创建验证请求
        /verify finish - 完成验证请求
        /verify clean - 清理非法验证请求
        """)

    @verify.command("create")
    async def verify_create(self, event: AstrMessageEvent, friend_code: str):
        """创建一个验证请求"""
        # 检查是否在白名单群组中
        group_id = event.get_group_id()
        if self.whitelist_groups and str(group_id) not in self.whitelist_groups:
            logger.debug(f"[LinkAmongUs] 群 {group_id} 不在白名单内，取消该任务。")
            return

        user_qq_id = event.get_sender_id()

        # 校验FriendCode格式：<字母>#<4位数字>，总字符数不超过25
        if len(friend_code) > 25:
            logger.debug(f"[LinkAmongUs] 用户使用的好友代码长度超过限制，拒绝使用此好友代码创建验证请求。")
            yield event.plain_result("创建验证请求失败，此好友代码非法。")
            return
            
        # 检查格式是否符合 <字母>#<4位数字>
        import re
        pattern = r'^[A-Za-z]+#\d{4}$'
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
            friend_code = latest_request["UserFriendCode"]
            
            if status in ["Created", "Retrying"]:
                server_name = self.api_config.get("APIConfig_ServerName")
                logger.warning(f"[LinkAmongUs] 用户 {user_qq_id} 已有进行中的验证请求，拒绝重复创建验证请求。")
                yield event.plain_result(
                    f"创建验证请求失败，你已于 {create_time} 使用 {friend_code} 创建了一个验证请求，需要加入服务器 {server_name} 房间 {verify_code} 以完成验证。\n"
                    f"请先完成当前验证。"
                )
                return
        logger.info(f"[LinkAmongUs] 用户 {user_qq_id} 使用 Among Us 账号 {friend_code} 创建了一个验证请求。")
        # 向API发送PUT请求创建验证请求
        api_key = self.api_config.get("APIConfig_Key")
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
        create_verify_config = self.verify_config.get("VerifyConfig_CreateVerfiyConfig", {})
        process_duration = create_verify_config.get("CreateVerfiyConfig_ProcessDuration")
        server_name = self.api_config.get("APIConfig_ServerName")
        
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

    @verify.command("finish")
    async def verify_finish(self, event: AstrMessageEvent):
        """完成一个验证请求"""
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
        api_key = self.api_config.get("APIConfig_Key")
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
    @verify.command("clean")
    async def verify_clean(self, event: AstrMessageEvent):
        """清理数据库中的非法验证请求"""
        # 获取超时时间配置
        create_verify_config = self.verify_config.get("VerifyConfig_CreateVerfiyConfig", {})
        process_duration = create_verify_config.get("CreateVerfiyConfig_ProcessDuration")
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

    @filter.permission_type(filter.PermissionType.ADMIN)
    @verify.command("query")
    async def verify_query(self, event: AstrMessageEvent, query_value: str):
        """查询指定用户的账号关联信息"""
        # 检查是否在白名单群组中
        group_id = event.get_group_id()
        if self.whitelist_groups and str(group_id) not in self.whitelist_groups:
            logger.debug(f"[LinkAmongUs] 群 {group_id} 不在白名单内，取消该任务。")
            return
            
        # 首先判断是否为FriendCode格式
        import re
        friend_code_pattern = r'^[A-Za-z]+#\d{4}$'
        is_friend_code = len(query_value) <= 25 and re.match(friend_code_pattern, query_value)
        
        # 如果不是FriendCode，检查是否为QQ号（5-13位纯数字）
        is_qq_number = query_value.isdigit() and 5 <= len(query_value) <= 13
        
        # 如果既不是FriendCode也不是QQ号，则返回错误
        if not is_friend_code and not is_qq_number:
            logger.debug(f"[LinkAmongUs] 管理员查询的用户非法，拒绝使用此参数查询用户信息。")
            yield event.plain_result("查询参数非法。")
            return
            
        # 查询用户绑定信息
        user_data = await self.query_user_verify_info(query_value)
        
        if user_data:
            # 记录管理员操作日志
            operator_qq_id = event.get_sender_id()
            logger.info(f"[LinkAmongUs] 管理员 {operator_qq_id} 查询了用户 {query_value} 的绑定信息。")
            
            # 格式化返回信息
            message = (
                f"用户 {user_data['UserQQID']} 账号关联信息：\n"
                f"账号名称：{user_data['UserAmongUsName']}\n"
                f"好友代码: {user_data['UserFriendCode']} ({user_data['UserHashedPuid']})\n"
                f"账号平台：{user_data['UserTokenPlatform']}\n"
                f"关联时间: {user_data['LastUpdated'].strftime('%Y-%m-%d %H:%M:%S')}"
            )
            yield event.plain_result(message)
        else:
            yield event.plain_result(f"未找到用户 {query_value} 的绑定信息。")

    @verify.command("info")
    async def verify_info(self, event: AstrMessageEvent):
        """查询当前用户的账号关联信息"""
        # 检查是否在白名单群组中
        group_id = event.get_group_id()
        if self.whitelist_groups and str(group_id) not in self.whitelist_groups:
            logger.debug(f"[LinkAmongUs] 群 {group_id} 不在白名单内，取消该任务。")
            return
            
        user_qq_id = event.get_sender_id()
        
        # 查询用户绑定信息
        user_data = await self.get_user_verify_info(user_qq_id)
        
        if user_data:
            # 格式化返回信息
            message = (
                f"用户 {user_qq_id} 账号关联信息：\n"
                f"账号名称：{user_data['UserAmongUsName']}\n"
                f"好友代码: {user_data['UserFriendCode']} ({user_data['UserHashedPuid']})\n"
                f"账号平台：{user_data['UserTokenPlatform']}\n"
                f"关联时间: {user_data['LastUpdated'].strftime('%Y-%m-%d %H:%M:%S')}"
            )
            yield event.plain_result(message)
        else:
            yield event.plain_result(f"用户 {user_qq_id} 尚未绑定 Among Us 账号。")

    @verify.command("help")
    async def verify_help(self, event: AstrMessageEvent):
        """发送帮助菜单"""
        # 检查是否在白名单群组中
        group_id = event.get_group_id()
        if self.whitelist_groups and str(group_id) not in self.whitelist_groups:
            logger.debug(f"[LinkAmongUs] 群 {group_id} 不在白名单内，取消该任务。")
            return
        yield event.plain_result(HELP_MENU)