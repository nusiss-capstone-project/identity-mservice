-- Add language to users
-- Target: MySQL 8.x, utf8mb4

ALTER TABLE `users`
  ADD COLUMN `language` VARCHAR(32) DEFAULT NULL AFTER `market`;
