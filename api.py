import asyncio
import aiohttp
from typing import Optional, Dict, Any
from astrbot.api import logger

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