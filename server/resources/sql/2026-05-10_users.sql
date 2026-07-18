-- Identity service — users table
-- Target: MySQL 8.x, utf8mb4

SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS `users` (
  `id` BIGINT NOT NULL AUTO_INCREMENT,
  `name` VARCHAR(255) DEFAULT NULL,
  `market` VARCHAR(64) DEFAULT NULL,
  `segment` VARCHAR(64) DEFAULT NULL,
  `kyc_status` VARCHAR(32) DEFAULT NULL,
  `risk_level` VARCHAR(32) DEFAULT NULL,
  `created_at` DATETIME(3) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
