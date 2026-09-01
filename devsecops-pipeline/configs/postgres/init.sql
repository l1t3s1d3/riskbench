-- Initialization script for the shared Postgres instance.
-- Creates databases and users for SonarQube and DefectDojo.

CREATE USER sonarqube WITH PASSWORD 'sonarqube';
CREATE DATABASE sonarqube OWNER sonarqube;

CREATE USER defectdojo WITH PASSWORD 'defectdojo';
CREATE DATABASE defectdojo OWNER defectdojo;
