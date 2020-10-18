CREATE TABLE `oauth_refresh_token` (
  `token_id` varchar(256) CHARACTER SET utf8mb4 DEFAULT NULL,
  `token` blob,
  `authentication` blob
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
