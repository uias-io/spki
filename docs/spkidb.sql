/*
 Target Server Type    : MySQL
 Target Server Version : 50744
 File Encoding         : 65001
*/

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
-- Table structure for pki_certificate
-- ----------------------------
DROP TABLE IF EXISTS `pki_certificate`;
CREATE TABLE `pki_certificate`  (
  `kid` int(11) NOT NULL AUTO_INCREMENT,
  `instance_id` char(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL,
  `certid` char(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL,
  `title` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT '证书的友好名称',
  `subject` varchar(512) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL DEFAULT NULL COMMENT '证书的Subject',
  `parent_id` char(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL DEFAULT NULL COMMENT '上级证书ID，根CA为NULL',
  `pathlev` tinyint(4) NOT NULL COMMENT '证书层级，ca:0、中间证书：1、服务证书2',
  `genre` tinyint(4) NOT NULL COMMENT '证书类型，根ca:1,中间ca2，服务证书3',
  `has_key` tinyint(1) NOT NULL COMMENT '是否有私钥 1有 0无',
  `issuecfg` json NOT NULL COMMENT '签发配置快照',
  `cert_req` text CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL COMMENT '证书请求文件',
  PRIMARY KEY (`kid`) USING BTREE,
  UNIQUE INDEX `uk_certid`(`certid`) USING BTREE,
  INDEX `idx_parent_id`(`parent_id`) USING BTREE,
  INDEX `idx_user_id`(`instance_id`) USING BTREE,
  INDEX `idx_genre`(`genre`) USING BTREE,
  INDEX `idx_has_key`(`has_key`) USING BTREE,
  CONSTRAINT `pki_certificate_ibfk_1` FOREIGN KEY (`instance_id`) REFERENCES `pki_instance` (`instance_id`) ON DELETE RESTRICT ON UPDATE CASCADE
) ENGINE = InnoDB AUTO_INCREMENT = 1000 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_bin ROW_FORMAT = DYNAMIC;

-- ----------------------------
-- Table structure for pki_instance
-- ----------------------------
DROP TABLE IF EXISTS `pki_instance`;
CREATE TABLE `pki_instance`  (
  `kid` int(11) NOT NULL AUTO_INCREMENT,
  `instance_id` char(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '实例ID',
  `domain_id` char(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '所属域（来自认证中心）',
  `cbc_status` varchar(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL DEFAULT 'normal' COMMENT 'CBC状态 normal/expired/arrears/suspended/unknown',
  `cbc_expire_time` bigint(20) NOT NULL COMMENT 'CBC 到期时间（毫秒）',
  `cbc_sync_time` bigint(20) NOT NULL COMMENT '最后一次同步时间（毫秒）',
  `create_time` bigint(20) NOT NULL COMMENT '创建时间（毫秒）',
  PRIMARY KEY (`kid`) USING BTREE,
  UNIQUE INDEX `uk_instance_id`(`instance_id`) USING BTREE,
  INDEX `idx_domain_id`(`domain_id`) USING BTREE,
  INDEX `idx_cbc_status`(`cbc_status`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 1000 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci ROW_FORMAT = DYNAMIC;

-- ----------------------------
-- Table structure for pki_private_key
-- ----------------------------
DROP TABLE IF EXISTS `pki_private_key`;
CREATE TABLE `pki_private_key`  (
  `kid` int(11) NOT NULL AUTO_INCREMENT,
  `instance_id` char(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL,
  `keyid` char(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL,
  `private_key` text CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL,
  `passphrase` varchar(512) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT '加密后的口令',
  `fingerprint` char(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '公钥SHA256指纹',
  `create_time` bigint(20) NULL DEFAULT NULL COMMENT '毫秒时间戳',
  PRIMARY KEY (`kid`) USING BTREE,
  UNIQUE INDEX `uk_pubkey_fingerprint`(`fingerprint`) USING BTREE,
  UNIQUE INDEX `uk_keyid`(`keyid`) USING BTREE,
  INDEX `instance_id`(`instance_id`) USING BTREE,
  CONSTRAINT `pki_private_key_ibfk_1` FOREIGN KEY (`instance_id`) REFERENCES `pki_instance` (`instance_id`) ON DELETE RESTRICT ON UPDATE CASCADE
) ENGINE = InnoDB AUTO_INCREMENT = 1000 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci ROW_FORMAT = DYNAMIC;

-- ----------------------------
-- Table structure for pki_version
-- ----------------------------
DROP TABLE IF EXISTS `pki_version`;
CREATE TABLE `pki_version`  (
  `kid` int(11) NOT NULL AUTO_INCREMENT,
  `instance_id` char(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL,
  `revision` int(11) NOT NULL COMMENT '版本号，从1递增',
  `certid` char(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL,
  `keyid` char(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL,
  `serial` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT '证书序列号',
  `fingerprint` char(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '证书SHA256指纹',
  `cert` text CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL COMMENT '证书文件主体',
  `effective_time` bigint(20) NULL DEFAULT NULL COMMENT '生效时间戳（毫秒）',
  `expiration_time` bigint(20) NULL DEFAULT NULL COMMENT '到期时间戳（毫秒）',
  `revocation_time` bigint(20) NULL DEFAULT NULL COMMENT '吊销时间戳（毫秒）',
  `revocation_code` tinyint(4) NULL DEFAULT NULL COMMENT '吊销原因码，RFC 5280 CRLReason，仅 state=R 时有值',
  `state` char(1) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL DEFAULT 'V' COMMENT 'V有效 R吊销 E过期',
  PRIMARY KEY (`kid`) USING BTREE,
  UNIQUE INDEX `uk_cert_fingerprint`(`fingerprint`) USING BTREE,
  UNIQUE INDEX `uk_cert_revision`(`certid`, `revision`) USING BTREE,
  INDEX `idx_expiration`(`expiration_time`) USING BTREE,
  INDEX `idx_serial`(`serial`) USING BTREE,
  INDEX `idx_state`(`state`) USING BTREE,
  INDEX `idx_keyid`(`keyid`) USING BTREE,
  INDEX `instance_id`(`instance_id`) USING BTREE,
  CONSTRAINT `fk_ver_key` FOREIGN KEY (`keyid`) REFERENCES `pki_private_key` (`keyid`) ON DELETE RESTRICT ON UPDATE CASCADE,
  CONSTRAINT `pki_version_ibfk_1` FOREIGN KEY (`certid`) REFERENCES `pki_certificate` (`certid`) ON DELETE RESTRICT ON UPDATE CASCADE,
  CONSTRAINT `pki_version_ibfk_2` FOREIGN KEY (`instance_id`) REFERENCES `pki_instance` (`instance_id`) ON DELETE RESTRICT ON UPDATE CASCADE
) ENGINE = InnoDB AUTO_INCREMENT = 1000 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci ROW_FORMAT = DYNAMIC;

SET FOREIGN_KEY_CHECKS = 1;
