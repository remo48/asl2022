DROP TABLE IF EXISTS `challenge`;

CREATE TABLE `challenge` (
  `id` INTEGER NOT NULL AUTO_INCREMENT,
  `challenge` varchar(1024) NOT NULL DEFAULT '',
  `serial_number` varchar(128) NOT NULL DEFAULT '',
  PRIMARY KEY (`id`)
);

DROP TABLE IF EXISTS `certificate`;

CREATE TABLE `certificate` (
  `id` INTEGER NOT NULL AUTO_INCREMENT,
  `uid` varchar(64) NOT NULL DEFAULT '',
  `serial_number` varchar(128) NOT NULL DEFAULT '',
  PRIMARY KEY (`id`)
);

INSERT INTO `certificate` VALUES (1, 'ad', '8');
