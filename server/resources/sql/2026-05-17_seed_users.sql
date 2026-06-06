-- Sample users and auth mappings for local development.
INSERT INTO `users` (`id`, `name`, `market`, `segment`, `kyc_status`, `risk_level`, `created_at`) VALUES
  (1,     'Demo User', 'US', 'NEW_USER', 'PASSED', 'LOW',  NOW(3)),
  (10001, 'Alice',     'US', 'NEW_USER', 'PASSED', 'LOW',  NOW(3)),
  (10002, 'Bob',       'US', 'NEW_USER', 'PASSED', 'LOW',  NOW(3))
ON DUPLICATE KEY UPDATE `name` = VALUES(`name`);

INSERT INTO `user_auth_mapping` (`clerk_user_id`, `email`, `internal_user_id`, `role`, `created_at`, `updated_at`) VALUES
  ('dev_bypass', 'demo@example.com', 1, 'admin', NOW(3), NOW(3))
ON DUPLICATE KEY UPDATE `email` = VALUES(`email`);
