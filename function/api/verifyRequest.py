import aiohttp
from typing import Dict, Any, Literal
from astrbot.api import logger

async def request_verify_api(session: aiohttp.ClientSession, api_endpoint: str, api_timeout: int, api_key: str, method: Literal["PUT", "GET", "DELETE"], credentials: str) -> Dict[str, Any]:
    """向 Nmpostor Verify API 发送请求，所有请求 API 的操作都应该使用此函数。
    
    Args:
        session: aiohttp 会话对象。
        api_endpoint: API 端点地址。
        api_timeout: API 请求超时时间。
        api_key: 请求使用的 API 密钥。
        method: 请求使用的方法，可选值为 `PUT`, `GET`, `DELETE`。
        credentials: 请求参数使用的凭证。`method` 不同，在此处提供的值也就不同：
            - PUT：friend_code (str)
            - GET & DELETE：verify_code (str)
    
    Returns:
        Dict[str, Any]: 操作结果字典，包含：
            - success: bool，操作是否成功。
            - data: dict[str, Any] | None，操作成功时返回的数据。`method` 为 `DELETE` 时始终返回 None。
            - message: str | None，操作失败时返回的错误信息，操作成功返回 None。
    """
    url = f"{api_endpoint}/api/verify"
    try:
        if method.upper() == 'PUT':
            # 创建验证请求
            payload = {
                "ApiKey": api_key,
                "FriendCode": credentials
            }
            logger.debug(f"[LinkAmongUs] 将使用账号 {credentials} 向 API 发送创建验证请求。")
            
            try:
                async with session.put(url, json=payload, timeout=api_timeout) as response:
                    if response.status == 200:
                        data = await response.json()
                        logger.debug(f"[LinkAmongUs] 成功使用账号 {credentials} 创建验证请求。")
                        return {"success": True, "data": data, "message": None}
                    else:
                        logger.error(f"[LinkAmongUs] 使用账号 {credentials} 创建验证请求失败，API 响应状态码为非 200 (响应 {response.status})。")
                        return {"success": False, "data": None, "message": f"API 响应状态码 {response.status}"}
            except aiohttp.ConnectionTimeoutError:
                logger.error(f"[LinkAmongUs] 使用账号 {credentials} 创建验证请求失败，API 请求超时。")
                return {"success": False, "data": None, "message": "API 请求超时"}
            except Exception as e:
                logger.error(f"[LinkAmongUs] 使用账号 {credentials} 创建验证请求失败，发生意外错误：{e}")
                return {"success": False, "data": None, "message": "发生意外错误"}
                
        elif method.upper() == 'GET':
            # 查询验证状态
            logger.debug(f"[LinkAmongUs] 正在查询房间 {credentials} 的验证请求状态。")
            query_url = f"{url}?apikey={api_key}&verifycode={credentials}"
            
            try:
                async with session.get(query_url, timeout=api_timeout) as response:
                    if response.status == 200:
                        logger.debug(f"[LinkAmongUs] 成功查询房间 {credentials} 的验证请求状态。")
                        return {"success": True, "data": await response.json(), "message": None}
                    else: 
                        logger.error(f"[LinkAmongUs] 查询房间 {credentials} 的验证请求状态失败，API 响应状态码为非 200 (响应 {response.status})。")
                        return {"success": False, "data": None, "message": f"API 响应状态码 {response.status}"}
            except aiohttp.ConnectionTimeoutError:
                logger.error(f"[LinkAmongUs] 查询房间 {credentials} 的验证请求状态失败，API 请求超时。")
                return {"success": False, "data": None, "message": "API 请求超时"}
            except Exception as e:
                logger.error(f"[LinkAmongUs] 查询房间 {credentials} 的验证请求状态失败，发生意外错误：{e}")
                return {"success": False, "data": None, "message": "发生意外错误"}
                
        elif method.upper() == 'DELETE':
            # 删除验证请求
            logger.debug(f"[LinkAmongUs] 准备删除房间 {credentials} 的验证请求。")
            payload = {
                "apikey": api_key,
                "verifycode": credentials
            }
            try:
                async with session.delete(url, json=payload, timeout=api_timeout) as response:
                    if response.status not in [200, 404]:
                        raise aiohttp.ClientResponseError
                    else:
                        logger.debug(f"[LinkAmongUs] 成功删除房间 {credentials} 的验证请求。") 
            except Exception as e:
                logger.warning(f"[LinkAmongUs] 验证请求删除失败，API 响应错误：{e}")
                logger.warning("[LinkAmongUs] 非打断操作，因为 Nmpostor 会自动销毁验证请求，将忽略该异常。")
            return {"success": True, "data": None, "message": None}
                
        else:
            logger.error(f"[LinkAmongUs] 程序尝试使用方法 {method} 向 API 进行请求，但函数尚不支持该请求方法。")
            return {"success": False, "data": None, "message": "不支持的请求方法"}
            
    except Exception as e:
        logger.error(f"[LinkAmongUs] 程序尝试使用方法 {method} 向 API 进行请求时发生错误: {e}")
        return {"success": False, "data": None, "message": "发生意外错误"}