CREATE DATABASE IF NOT EXISTS sadb;

USE sadb;

-- IV_LEN should probably not have that default -- to be reviewed.

CREATE TABLE IF NOT EXISTS security_associations
(
  spi INT NOT NULL
  ,ekid VARCHAR(100) CHARACTER SET utf8 DEFAULT NULL -- 'EG, for KMC Crypto KeyRef, 'kmc/test/KEY130', for libgcrypt '130'
  ,akid VARCHAR(100) CHARACTER SET utf8 DEFAULT NULL -- Same as ekid
  ,sa_state SMALLINT NOT NULL DEFAULT 0
  ,tfvn TINYINT NOT NULL
  ,scid SMALLINT NOT NULL
  ,vcid TINYINT NOT NULL
  ,mapid TINYINT NOT NULL DEFAULT 0
  ,lpid SMALLINT
  ,est SMALLINT NOT NULL DEFAULT 0
  ,ast SMALLINT NOT NULL DEFAULT 0
  ,shivf_len SMALLINT NOT NULL DEFAULT 0
  ,shsnf_len SMALLINT NOT NULL DEFAULT 0
  ,shplf_len SMALLINT NOT NULL DEFAULT 0
  ,stmacf_len SMALLINT NOT NULL DEFAULT 0
  ,ecs_len SMALLINT NOT NULL DEFAULT 1
  ,ecs VARBINARY(4) NOT NULL DEFAULT X'01' -- ECS_SIZE=4
  ,iv_len SMALLINT NOT NULL DEFAULT 0
  ,iv VARBINARY(20) DEFAULT NULL -- IV_SIZE=12
  ,acs_len SMALLINT NOT NULL DEFAULT 0
  ,acs VARBINARY(4) NOT NULL DEFAULT X'00'
  ,abm_len MEDIUMINT
  ,abm VARBINARY(1024) NOT NULL DEFAULT X'0000FC0000FFFF000000000000000000000000' -- ABM_SIZE=1024
  ,arsn_len SMALLINT NOT NULL DEFAULT 0
  ,arsn VARBINARY(20) NOT NULL DEFAULT X'0000000000000000000000000000000000000000' -- ARSN_SIZE=20 , TBD why so large...
  ,arsnw SMALLINT NOT NULL DEFAULT 0 -- ARSNW_SIZE=1
);

create unique index if not exists main_spi on security_associations (spi,scid,vcid,tfvn,mapid);
