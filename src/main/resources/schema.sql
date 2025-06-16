-- Create USERS table
CREATE TABLE users (
                       username VARCHAR2(50 CHAR) NOT NULL PRIMARY KEY,
                       password VARCHAR2(500 CHAR) NOT NULL,
                       enabled CHAR(1) NOT NULL  -- 'Y' or 'N' to simulate boolean
);

-- Create AUTHORITIES table
CREATE TABLE authorities (
                             username VARCHAR2(50 CHAR) NOT NULL,
                             authority VARCHAR2(50 CHAR) NOT NULL,
                             CONSTRAINT fk_authorities_users FOREIGN KEY (username)
                                 REFERENCES users (username)
);

-- Create unique index on AUTHORITIES
CREATE UNIQUE INDEX ix_auth_username
    ON authorities (username, authority);
