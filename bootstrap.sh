#!/bin/bash
sqlite3 sensor_data.db "
CREATE TABLE IF NOT EXISTS sensor_data (
  timestamp TEXT NOT NULL,
  sensor_name TEXT NOT NULL,
  field TEXT NOT NULL,
  value TEXT NOT NULL,
  type TEXT NOT NULL
);
"
