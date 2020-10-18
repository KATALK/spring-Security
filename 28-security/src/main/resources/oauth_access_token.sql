CREATE TABLE `oauth_access_token` (
  `token_id` varchar(256) CHARACTER SET utf8mb4 DEFAULT NULL,
  `token` blob,
  `authentication_id` varchar(128) CHARACTER SET utf8mb4 NOT NULL,
  `user_name` varchar(256) CHARACTER SET utf8mb4 DEFAULT NULL,
  `client_id` varchar(256) CHARACTER SET utf8mb4 DEFAULT NULL,
  `authentication` blob,
  `refresh_token` varchar(256) CHARACTER SET utf8mb4 DEFAULT NULL,
  PRIMARY KEY (`authentication_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
