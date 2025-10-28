-- phpMyAdmin SQL Dump
-- version 5.2.3
-- https://www.phpmyadmin.net/
--
-- 主机： MySQL:3306
-- 生成日期： 2025-10-28 09:39:07
-- 服务器版本： 8.4.7
-- PHP 版本： 8.3.26

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- 数据库： `LinkAmongUs`
--

-- --------------------------------------------------------

--
-- 表的结构 `VerifyUserData`
--

CREATE TABLE `VerifyUserData` (
  `SQLID` smallint NOT NULL,
  `LastUpdated` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `UserQQName` varchar(40) DEFAULT NULL,
  `UserQQID` varchar(13) NOT NULL,
  `UserAmongUsName` varchar(11) DEFAULT NULL,
  `UserFriendCode` varchar(32) NOT NULL,
  `UserPuid` varchar(48) NOT NULL,
  `UserHashedPuid` varchar(11) NOT NULL,
  `UserUdpPlatform` varchar(32) NOT NULL,
  `UserTokenPlatform` varchar(32) NOT NULL,
  `UserUdpIP` varchar(32) NOT NULL,
  `UserHttpIP` varchar(128) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

--
-- 转储表的索引
--

--
-- 表的索引 `VerifyUserData`
--
ALTER TABLE `VerifyUserData`
  ADD PRIMARY KEY (`SQLID`),
  ADD UNIQUE KEY `UserQQID` (`UserQQID`,`UserFriendCode`,`UserPuid`,`UserHashedPuid`);

--
-- 在导出的表使用AUTO_INCREMENT
--

--
-- 使用表AUTO_INCREMENT `VerifyUserData`
--
ALTER TABLE `VerifyUserData`
  MODIFY `SQLID` smallint NOT NULL AUTO_INCREMENT;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
