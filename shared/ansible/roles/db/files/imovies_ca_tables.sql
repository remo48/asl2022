
CREATE TABLE `challenge` (
  `uid` varchar(64) NOT NULL DEFAULT '',
  `challenge` varchar(1024) NOT NULL DEFAULT '',
  `serial_number` varchar(128) NOT NULL DEFAULT '',
  PRIMARY KEY (`uid`)
);


CREATE TABLE `certificate` (
  `uid` varchar(64) NOT NULL DEFAULT '',
  `serial_number` varchar(128) NOT NULL DEFAULT '',
  PRIMARY KEY (`uid`)
);
