CREATE DATABASE IF NOT EXISTS packeteye;

USE packeteye;

CREATE TABLE packets (
  id INT AUTO_INCREMENT PRIMARY KEY,
  timestamp DATETIME,
  src VARCHAR(100),
  dst VARCHAR(100),
  protocol VARCHAR(50),
  summary TEXT
);