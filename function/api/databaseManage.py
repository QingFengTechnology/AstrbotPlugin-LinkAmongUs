from typing import Any, Dict
import aiomysql
from astrbot.api import logger

async def database_manage(db_pool: aiomysql.Pool, table: str, method: str, latest: bool = False, **kwargs) -> Dict[str, Any]:
    """对 MySQL 数据库进行统一操作。
    
    Args:
        db_pool: 数据库连接池。
        table: 要操作的MySQL数据表名，可选值为 `VerifyUserData`、`VerifyLog`、`VerifyGroupLog`。
        method: 操作数据库的方法，可选值为 `get`、`update`、`insert`、`check`。
        latest: 仅 `method` 为 `get` 时有效，是否只返回最新的一条数据。
        **kwargs: 根据不同操作和表提供相应的参数：
            对于 VerifyUserData 表：
                - get: `user_qq_id` | `friend_code` (str)
                - update: `user_qq_id` (str), `user_data` (dict)
                - insert: `user_data` (dict)
            对于 VerifyLog 表：
                - get: `user_qq_id` (str)
                - update: `sql_id` (int), `status` (str)
                - insert: `user_qq_id` (str), `friend_code` (str), `verify_code` (str), `status` (str, 默认 Created)
            对于 VerifyGroupLog 表：
                - get: `user_qq_id` | `status` (str), `status` (str, 可选)
                - update: `sql_id` (int), `status` (str) 
                - insert: `user_qq_id` (str), `group_id` (str), `status` (str, 默认 Created)
            对于任意表：
                - check: `structure` (str)
    
    Returns:
        Dict[str, Any]: 操作结果字典，包含：
            - success: bool，操作是否成功
            - data: Any，仅 `method` 为 `get` 时才会有内容，返回的数据对象。对于其他方法返回 `None`。
            - message: str | None，发生错误时返回的信息。操作成功返回 `None`。
    """
    if not db_pool:
        logger.error("[LinkAmongUs] 数据库操作失败：数据库连接池未初始化。")
        return {"success": False, "data": None, "message": "数据库连接池未初始化"}

    try:
        async with db_pool.acquire() as conn:
            async with conn.cursor() as cursor:
                if method == "check":
                    structure = kwargs.get('structure')
                    if not structure:
                        logger.error("[LinkAmongUs] 插件尝试检查数据表，但未提供 structure 参数。")
                        return {"success": False, "data": None, "message": "参数 structure 缺失"}
                    
                    logger.debug(f"[LinkAmongUs] 正在检查数据表 {table} 是否存在。")
                    await cursor.execute("SHOW TABLES LIKE %s", (table,))
                    result = await cursor.fetchone()
                    
                    if result:
                        logger.debug(f"[LinkAmongUs] 数据表 {table} 已存在。")
                        return {"success": True, "data": {"exists": True}, "message": None}
                    else:
                        logger.debug(f"[LinkAmongUs] 数据表 {table} 不存在，将创建该数据表。")
                        try:
                            await cursor.execute(structure)
                            logger.debug(f"[LinkAmongUs] 数据表 {table} 创建成功。")
                            return {"success": True, "data": {"exists": False, "created": True}, "message": None}
                        except Exception as e:
                            logger.error(f"[LinkAmongUs] 创建数据表 {table} 时发生错误: {e}")
                            return {"success": False, "data": None, "message": "发生意外错误"}
                elif table == "VerifyUserData":
                    return await _handle_verify_user_data(cursor, method, latest, **kwargs)
                elif table == "VerifyLog":
                    return await _handle_verify_log(cursor, method, latest, **kwargs)
                elif table == "VerifyGroupLog":
                    return await _handle_verify_group_log(cursor, method, latest, **kwargs)
                else:
                    logger.error(f"[LinkAmongUs] 插件尝试操作数据表 {table}，但 API 尚不支持或数据表不存在。")
                    return {"success": False, "data": None, "message": "目标数据表非法"}

    except Exception as e:
        logger.error(f"[LinkAmongUs] 执行数据库操作时发生意外错误: {e}")
        return {"success": False, "data": None, "message": "发生意外错误"}

async def _handle_verify_user_data(cursor, method: str, latest: bool, **kwargs) -> Dict[str, Any]:
    """处理 VerifyUserData 表的操作"""
    try:
        if method == "get":
            user_qq_id = kwargs.get('user_qq_id')
            friend_code = kwargs.get('friend_code')
            
            if not user_qq_id and not friend_code:
                logger.error("[LinkAmongUs] 插件尝试查询用户身份数据，但未提供 user_qq_id 或 friend_code 参数。")
                return {"success": False, "data": None, "message": "参数 user_qq_id 或 friend_code 缺失"}
            
            # 根据提供的参数构建查询条件
            if user_qq_id:
                logger.debug(f"[LinkAmongUs] 正在查询用户 {user_qq_id} 的身份数据。")
                await cursor.execute(
                    "SELECT * FROM VerifyUserData WHERE UserQQID = %s",
                    (user_qq_id,)
                )
            else:
                logger.debug(f"[LinkAmongUs] 正在查询好友代码 {friend_code} 的身份数据。")
                await cursor.execute(
                    "SELECT * FROM VerifyUserData WHERE UserFriendCode = %s",
                    (friend_code,)
                )
            result = await cursor.fetchone()
            if result:
                columns = [desc[0] for desc in cursor.description]
                result_dict = dict(zip(columns, result))
                if user_qq_id:
                    logger.debug(f"[LinkAmongUs] 成功查询用户 {user_qq_id} 的身份数据。")
                else:
                    logger.debug(f"[LinkAmongUs] 成功查询好友代码 {friend_code} 关联的身份数据。")
                return {"success": True, "data": result_dict, "message": None}
            if user_qq_id:
                logger.debug(f"[LinkAmongUs] 未查询到用户 {user_qq_id} 的身份数据。")
            else:
                logger.debug(f"[LinkAmongUs] 未查询到好友代码 {friend_code} 关联的身份数据。")
            return {"success": True, "data": None, "message": None}

        elif method == "update":
            user_qq_id = kwargs.get('user_qq_id')
            user_data = kwargs.get('user_data')
            if not user_qq_id or not user_data:
                logger.error("[LinkAmongUs] 插件尝试更新用户身份数据，但未提供 user_qq_id 或 user_data 参数。")
                return {"success": False, "data": None, "message": "参数 user_qq_id 或 user_data 缺失"}
            
            logger.debug(f"[LinkAmongUs] 正在更新用户 {user_qq_id} 的身份数据。")
            set_clause = ", ".join([f"{key} = %s" for key in user_data.keys()])
            values = list(user_data.values()) + [user_qq_id]
            await cursor.execute(
                f"UPDATE VerifyUserData SET {set_clause} WHERE UserQQID = %s",
                values
            )
            logger.debug(f"[LinkAmongUs] 成功更新用户 {user_qq_id} 的身份数据。")
            return {"success": True, "data": None, "message": None}

        elif method == "insert":
            user_data = kwargs.get('user_data')
            if not user_data:
                logger.error("[LinkAmongUs] 插件尝试写入用户身份数据，但未提供 user_data 参数。")
                return {"success": False, "data": None, "message": "参数 user_data 缺失"}
            
            logger.debug(f"[LinkAmongUs] 正在写入用户 {user_data.get('UserQQID')} 的身份数据。")
            columns = ", ".join(user_data.keys())
            placeholders = ", ".join(["%s"] * len(user_data))
            values = list(user_data.values())
            await cursor.execute(
                f"INSERT INTO VerifyUserData ({columns}) VALUES ({placeholders})",
                values
            )
            logger.debug(f"[LinkAmongUs] 成功写入用户 {user_data.get('UserQQID')} 的身份数据。")
            return {"success": True, "data": None, "message": None}

        else:
            logger.error(f"[LinkAmongUs] 插件尝试操作数据表 VerifyUserData，但使用的请求方法 API 尚不支持。")
            return {"success": False, "data": None, "message": "不支持的请求方法"}

    except Exception as e:
        logger.error(f"[LinkAmongUs] 处理 VerifyUserData 表操作时发生错误: {e}")
        return {"success": False, "data": None, "message": "发生意外错误"}

async def _handle_verify_log(cursor, method: str, latest: bool, **kwargs) -> Dict[str, Any]:
    """处理 VerifyLog 表的操作"""
    try:
        if method == "get":
            user_qq_id = kwargs.get('user_qq_id')
            if user_qq_id:
                logger.debug(f"[LinkAmongUs] 正在查询用户 {user_qq_id} 的验证日志。")
                if latest:
                    await cursor.execute(
                        "SELECT * FROM VerifyLog WHERE UserQQID = %s ORDER BY CreateTime DESC LIMIT 1",
                        (user_qq_id,)
                    )
                else:
                    await cursor.execute(
                        "SELECT * FROM VerifyLog WHERE UserQQID = %s",
                        (user_qq_id,)
                    )
                result = await cursor.fetchone()
                if result:
                    columns = [desc[0] for desc in cursor.description]
                    result_dict = dict(zip(columns, result))
                    logger.debug(f"[LinkAmongUs] 成功查询到用户 {user_qq_id} 的验证日志。")
                    return {"success": True, "data": result_dict, "message": None}
                logger.debug(f"[LinkAmongUs] 未查询到用户 {user_qq_id} 的验证日志。")
                return {"success": True, "data": None, "message": None}
            else:
                logger.error("[LinkAmongUs] 插件尝试查询用户验证日志，但未提供 user_qq_id 参数。")
                return {"success": False, "data": None, "message": "参数 user_qq_id 缺失"}

        elif method == "update":
            sql_id = kwargs.get('sql_id')
            status = kwargs.get('status')
            if not sql_id or not status:
                logger.error("[LinkAmongUs] 插件尝试更新验证日志状态，但未提供 sql_id 或 status 参数。")
                return {"success": False, "data": None, "message": "参数 sql_id 或 status 缺失"}
            
            logger.debug(f"[LinkAmongUs] 正在更新验证日志 {sql_id} 的状态为 {status}。")
            await cursor.execute(
                "UPDATE VerifyLog SET Status = %s WHERE SQLID = %s",
                (status, sql_id)
            )
            logger.debug(f"[LinkAmongUs] 成功更新验证日志 {sql_id} 的状态为 {status}。")
            return {"success": True, "data": None, "message": None}

        elif method == "insert":
            user_qq_id = kwargs.get('user_qq_id')
            friend_code = kwargs.get('friend_code')
            verify_code = kwargs.get('verify_code')
            status = kwargs.get('status', 'Created')
            
            if not user_qq_id or not friend_code or not verify_code:
                logger.error("[LinkAmongUs] 插件尝试写入用户验证日志，但未提供 user_qq_id、friend_code 或 verify_code 参数。")
                return {"success": False, "data": None, "message": "参数 user_qq_id 或 friend_code 或 verify_code 缺失"}
            
            logger.debug(f"[LinkAmongUs] 正在写入用户 {user_qq_id} 的验证日志。")
            await cursor.execute(
                "INSERT INTO VerifyLog (Status, UserQQID, UserFriendCode, VerifyCode) VALUES (%s, %s, %s, %s)",
                (status, user_qq_id, friend_code, verify_code)
            )
            logger.debug(f"[LinkAmongUs] 成功写入用户 {user_qq_id} 的验证日志。")
            return {"success": True, "data": None, "message": None}

        else:
            logger.error(f"[LinkAmongUs] 插件尝试操作数据表 VerifyLog，但使用的请求方法 API 尚不支持。")
            return {"success": False, "data": None, "message": f"不支持的请求方法"}

    except Exception as e:
        logger.error(f"[LinkAmongUs] 处理 VerifyLog 表操作时发生错误: {e}")
        return {"success": False, "data": None, "message": "发生意外错误"}

async def _handle_verify_group_log(cursor, method: str, latest: bool, **kwargs) -> Dict[str, Any]:
    """处理 VerifyGroupLog 表的操作"""
    try:
        if method == "get":
            user_qq_id = kwargs.get('user_qq_id')
            status = kwargs.get('status')
            
            # 构建查询条件
            where_conditions = []
            params = []
            
            if user_qq_id:
                where_conditions.append("VerifyUserID = %s")
                params.append(user_qq_id)
            
            if status:
                where_conditions.append("Status = %s")
                params.append(status)
            
            # 如果没有提供任何查询条件，则返回错误
            if not where_conditions:
                logger.error("[LinkAmongUs] 插件尝试查询入群验证日志，但未提供 user_qq_id 或 status 参数。")
                return {"success": False, "data": None, "message": "至少需要提供 user_qq_id 或 status 参数中的一个"}
            
            where_clause = " AND ".join(where_conditions)
            query_desc = f"用户 {user_qq_id}" if user_qq_id else f"状态为 {status}"
            logger.debug(f"[LinkAmongUs] 正在查询{query_desc} 的入群验证日志。")
            
            if latest:
                await cursor.execute(
                    f"SELECT * FROM VerifyGroupLog WHERE {where_clause} ORDER BY CreateTime DESC LIMIT 1",
                    params
                )
                result = await cursor.fetchone()
                if result:
                    columns = [desc[0] for desc in cursor.description]
                    result_dict = dict(zip(columns, result))
                    logger.debug(f"[LinkAmongUs] 成功查询到{query_desc} 的入群验证日志。")
                    return {"success": True, "data": result_dict, "message": None}
                logger.debug(f"[LinkAmongUs] 未查询到{query_desc} 的入群验证日志。")
                return {"success": True, "data": None, "message": None}
            else:
                await cursor.execute(
                    f"SELECT * FROM VerifyGroupLog WHERE {where_clause}",
                    params
                )
                results = await cursor.fetchall()
                if results:
                    columns = [desc[0] for desc in cursor.description]
                    results_list = [dict(zip(columns, row)) for row in results]
                    logger.debug(f"[LinkAmongUs] 成功查询到{query_desc} 的入群验证日志。")
                    return {"success": True, "data": results_list, "message": None}
                logger.debug(f"[LinkAmongUs] 未查询到{query_desc} 的入群验证日志。")
                return {"success": True, "data": [], "message": None}

        elif method == "update":
            sql_id = kwargs.get('sql_id')
            status = kwargs.get('status')
            if not sql_id or not status:
                logger.error("[LinkAmongUs] 插件尝试更新入群验证日志状态，但未提供 sql_id 或 status 参数。")
                return {"success": False, "data": None, "message": "参数 sql_id 或 status 缺失"}
            
            logger.debug(f"[LinkAmongUs] 正在更新入群验证日志 {sql_id} 的状态为 {status}。")
            await cursor.execute(
                "UPDATE VerifyGroupLog SET Status = %s WHERE SQLID = %s",
                (status, sql_id)
            )
            logger.debug(f"[LinkAmongUs] 成功更新入群验证日志 {sql_id} 的状态为 {status}。")
            return {"success": True, "data": None, "message": None}

        elif method == "insert":
            user_qq_id = kwargs.get('user_qq_id')
            group_id = kwargs.get('group_id')
            status = kwargs.get('status', 'Created')
            
            if not user_qq_id or not group_id:
                return {"success": False, "data": None, "message": "参数 user_qq_id 或 group_id 缺失"}
            
            logger.debug(f"[LinkAmongUs] 正在写入用户 {user_qq_id} 的群组验证日志。")
            await cursor.execute(
                "INSERT INTO VerifyGroupLog (Status, VerifyUserID, BanGroupID, KickTime) VALUES (%s, %s, %s, NOW())",
                (status, user_qq_id, group_id)
            )
            logger.debug(f"[LinkAmongUs] 成功写入用户 {user_qq_id} 的入群验证日志。")
            return {"success": True, "data": None, "message": None}

        else:
            logger.error(f"[LinkAmongUs] 插件尝试操作数据表 VerifyGroupLog，但使用的请求方法 API 尚不支持。")
            return {"success": False, "data": None, "message": "不支持的操作方法"}

    except Exception as e:
        logger.error(f"[LinkAmongUs] 处理 VerifyGroupLog 表操作时发生错误: {e}")
        return {"success": False, "data": None, "message": "发生意外错误"}