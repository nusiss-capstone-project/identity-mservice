-- Clerk identity mapping for auth.
CREATE TABLE IF NOT EXISTS `user_auth_mapping` (
  `id` BIGINT NOT NULL AUTO_INCREMENT,
  `clerk_user_id` VARCHAR(128) NOT NULL,
  `email` VARCHAR(255) DEFAULT NULL,
  `internal_user_id` BIGINT NOT NULL,
  `role` VARCHAR(32) NOT NULL COMMENT 'admin or user',
  `created_at` DATETIME(3) DEFAULT NULL,
  `updated_at` DATETIME(3) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_user_auth_mapping_clerk_user_id` (`clerk_user_id`),
  KEY `idx_user_auth_mapping_internal_user_id` (`internal_user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
