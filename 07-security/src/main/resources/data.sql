


DROP TABLE IF EXISTS `authorities`;
CREATE TABLE `authorities` (
  `username` varchar(100) NOT NULL,
  `authority` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Records of authorities
-- ----------------------------
INSERT INTO `authorities` VALUES ('admin', 'ONE');
INSERT INTO `authorities` VALUES ('user', 'TWO');

-- ----------------------------
-- Table structure for users
-- ----------------------------
DROP TABLE IF EXISTS `users`;
CREATE TABLE `users` (
  `username` varchar(100) NOT NULL,
  `password` varchar(255) DEFAULT NULL,
  `enabled` tinyint(1) DEFAULT NULL,
  PRIMARY KEY (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;





INSERT INTO `users` VALUES ('admin', '{noop}admin', '1');
INSERT INTO `users` VALUES ('user', '{noop}123456', '1');
