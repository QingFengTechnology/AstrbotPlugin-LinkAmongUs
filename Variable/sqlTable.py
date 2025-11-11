VERIFY_LOG = """
CREATE TABLE IF NOT EXISTS VerifyLog (
SQLID smallint NOT NULL AUTO_INCREMENT,
CreateTime datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
Status set('Created','Retrying','Verified','Cancelled','Expired') CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
UserQQID varchar(13) NOT NULL,
UserFriendCode varchar(32) NOT NULL,
VerifyCode varchar(7) NOT NULL,
PRIMARY KEY (SQLID)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci
"""

VERIFY_USER_DATA = """
CREATE TABLE IF NOT EXISTS VerifyUserData (
QLID smallint NOT NULL AUTO_INCREMENT,
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
"""