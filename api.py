import aiohttp
from typing import Optional, Dict, Any
from astrbot.api import logger
import aiomysql

async def request_verify_api(session: aiohttp.ClientSession, api_endpoint: str, api_timeout: int, method: str, api_key: str, **kwargs) -> Optional[Dict[str, Any]]:
    """向 Nmpostor Verify API 发送请求，所有请求 API 的操作都应该使用此函数。
    
    Args:
        session: aiohttp 会话对象。
        api_endpoint: API 端点地址。
        api_timeout: API 请求超时时间。
        method: 请求使用的 HTTP 方法，选值为`PUT`, `GET`, `DELETE`。
        api_key: 请求使用的 API 密钥。
        **kwargs: 提供的额外参数。`method` 不同，提供的参数也不同：`GET` 和 `DELETE` 需要提供 `verify_code`；`PUT` 需要提供 `friend_code`。
    """
    url = f"{api_endpoint}/api/verify"
    try:
        if method.upper() == 'PUT':
            # 创建验证请求
            friend_code = kwargs.get('friend_code')
            if not friend_code:
                logger.error("[LinkAmongUs] 创建验证请求需要好友代码，但调用方法时未提供此参数。")
                return None
                
            payload = {
                "ApiKey": api_key,
                "FriendCode": friend_code
            }
            logger.info(f"[LinkAmongUs] 将使用账号 {friend_code} 向 API 发送创建验证请求。")
            
            async with session.put(url, json=payload, timeout=api_timeout) as response:
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
                
        elif method.upper() == 'GET':
            # 查询验证状态
            verify_code = kwargs.get('verify_code')
            if not verify_code:
                logger.error("[LinkAmongUs] 查询验证状态需要房间代码，但调用方法时未提供此参数。")
                return None
                
            logger.info(f"[LinkAmongUs] 正在查询房间 {verify_code} 的验证状态。")
            query_url = f"{url}?apikey={api_key}&verifycode={verify_code}"
            
            async with session.get(query_url, timeout=api_timeout) as response:
                if response.status == 200:
                    logger.info(f"[LinkAmongUs] 成功查询房间 {verify_code} 的验证状态。")
                    return await response.json()
                logger.error(f"[LinkAmongUs] 查询房间 {verify_code} 验证状态失败，API 返回状态码 {response.status}。")
                return None
                
        elif method.upper() == 'DELETE':
            # 删除验证请求
            verify_code = kwargs.get('verify_code')
            if not verify_code:
                logger.error("[LinkAmongUs] 删除验证请求缺少verify_code参数")
                return False
                
            logger.debug(f"[LinkAmongUs] 准备删除房间 {verify_code} 的验证请求。")
            payload = {
                "apikey": api_key,
                "verifycode": verify_code
            }
            
            async with session.delete(url, json=payload, timeout=api_timeout) as response:
                if response.status == 200:
                    logger.debug(f"[LinkAmongUs] 成功删除房间 {verify_code} 的验证请求。")
                else:
                    logger.warning(f"[LinkAmongUs] 验证请求删除失败，状态码: {response.status}, 验证码: {verify_code}")
                return response.status == 200
                
        else:
            logger.error(f"[LinkAmongUs] 程序尝试使用方法 {method} 向 API 进行请求，但函数尚不支持该请求方法。")
            return None if method != 'DELETE' else False
            
    except Exception as e:
        logger.error(f"[LinkAmongUs] 程序尝试使用方法 {method} 向 API 进行请求时发生错误: {e}")
        return None if method != 'DELETE' else False

async def database_manage(db_pool: aiomysql.Pool, operation: str, **kwargs) -> Optional[Any]:
    """对 MySQL 数据库进行操作。
    
    Args:
        db_pool: 数据库连接池。
        operation: 要执行的操作，可选值：
            - check_user_exists: 检查用户QQ号是否已存在于数据库
            - check_friend_code_exists: 检查好友代码是否已存在于数据库
            - get_active_verify_request: 获取用户最新的进行中的验证请求
            - update_verify_log_status: 更新验证日志状态
            - insert_verify_user_data: 写入用户身份数据
        **kwargs: 根据不同操作提供相应的参数。
    """
    if not db_pool:
        logger.error("[LinkAmongUs] 数据库操作失败：数据库连接池未初始化。")
        return None

    try:
        async with db_pool.acquire() as conn:
            async with conn.cursor() as cursor:
                if operation == "check_user_exists":
                    # 检查用户QQ号是否已存在于数据库
                    user_qq_id = kwargs.get('user_qq_id')
                    if not user_qq_id:
                        logger.error("[LinkAmongUs] 检查用户是否存在需要用户QQ号，但调用方法时未提供此参数。")
                        return None
                    
                    logger.info(f"[LinkAmongUs] 正在验证用户 {user_qq_id} 是否已关联 Among Us 账号。")
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

                elif operation == "check_friend_code_exists":
                    # 检查好友代码是否已存在于数据库
                    friend_code = kwargs.get('friend_code')
                    if not friend_code:
                        logger.error("[LinkAmongUs] 检查好友代码是否存在需要好友代码，但调用方法时未提供此参数。")
                        return None
                    
                    logger.info(f"[LinkAmongUs] 正在验证好友代码 {friend_code} 是否已关联 QQ 号。")
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
                        return result_dict
                    logger.info(f"[LinkAmongUs] 好友代码 {friend_code} 尚未关联 QQ 号。")
                    return None

                elif operation == "get_active_verify_request":
                    # 获取用户最新的进行中的验证请求
                    user_qq_id = kwargs.get('user_qq_id')
                    if not user_qq_id:
                        logger.error("[LinkAmongUs] 获取活跃验证请求需要用户QQ号，但调用方法时未提供此参数。")
                        return None
                    
                    logger.info(f"[LinkAmongUs] 正在获取用户 {user_qq_id} 最新的进行中的验证请求。")
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

                elif operation == "update_verify_log_status":
                    # 更新验证日志状态
                    sql_id = kwargs.get('sql_id')
                    status = kwargs.get('status')
                    if not sql_id or not status:
                        logger.error("[LinkAmongUs] 更新验证日志状态需要SQL ID和状态，但调用方法时未提供这些参数。")
                        return False
                    
                    logger.info(f"[LinkAmongUs] 正在将 ID {sql_id} 的验证日志状态更新为 {status}。")
                    await cursor.execute(
                        "UPDATE VerifyLog SET Status = %s WHERE SQLID = %s",
                        (status, sql_id)
                    )
                    logger.info(f"[LinkAmongUs] 已将 ID {sql_id} 的验证日志更新为 {status}。")
                    return True

                elif operation == "insert_verify_user_data":
                    # 写入用户身份数据
                    user_data = kwargs.get('user_data')
                    if not user_data:
                        logger.error("[LinkAmongUs] 插入用户身份数据需要用户数据，但调用方法时未提供此参数。")
                        return False
                    
                    logger.info(f"[LinkAmongUs] 准备写入用户 {user_data.get('UserQQID')}({user_data.get('UserFriendCode')}) 的身份数据。")
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

                else:
                    logger.error(f"[LinkAmongUs] 程序尝试执行数据库操作 {operation}，但函数尚不支持该操作。")
                    return None

    except Exception as e:
        logger.error(f"[LinkAmongUs] 执行数据库操作 {operation} 时发生错误: {e}")
        return None if operation not in ["update_verify_log_status", "insert_verify_user_data"] else False