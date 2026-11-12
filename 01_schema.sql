-- =====================================================================
-- Software Dependency Vulnerability Tracker  |  DBMS Mini Project
-- File 1: DDL (database + tables + constraints + indexes)
-- Run in MySQL Workbench (MySQL 8.0+)
-- =====================================================================

DROP DATABASE IF EXISTS vuln_tracker;
CREATE DATABASE vuln_tracker CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
USE vuln_tracker;

-- ---------------------------------------------------------------------
-- ROLE  (+ multivalued attribute "permissions" -> role_permission)
-- ---------------------------------------------------------------------
CREATE TABLE role (
    role_id      INT AUTO_INCREMENT PRIMARY KEY,
    role_name    VARCHAR(30)  NOT NULL UNIQUE,
    description  VARCHAR(200)
) ENGINE=InnoDB;

CREATE TABLE role_permission (
    role_id     INT         NOT NULL,
    permission  VARCHAR(40) NOT NULL,
    PRIMARY KEY (role_id, permission),
    CONSTRAINT fk_rp_role FOREIGN KEY (role_id) REFERENCES role(role_id)
        ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- DEVELOPER  (composite "name" -> first_name,last_name;
--             multivalued "phone_no" -> developer_phone)
-- ---------------------------------------------------------------------
CREATE TABLE developer (
    developer_id   INT AUTO_INCREMENT PRIMARY KEY,
    first_name     VARCHAR(50)  NOT NULL,
    last_name      VARCHAR(50)  NOT NULL,
    email          VARCHAR(100) NOT NULL UNIQUE,
    password_hash  CHAR(64)     NOT NULL,              -- SHA-256 hex
    joined_date    DATE         NOT NULL DEFAULT (CURRENT_DATE),
    role_id        INT          NOT NULL,              -- has_role (1:N)
    CONSTRAINT chk_dev_email CHECK (email LIKE '%_@_%._%'),
    CONSTRAINT fk_dev_role FOREIGN KEY (role_id) REFERENCES role(role_id)
        ON DELETE RESTRICT ON UPDATE CASCADE
) ENGINE=InnoDB;

CREATE TABLE developer_phone (
    developer_id INT         NOT NULL,
    phone_no     VARCHAR(15) NOT NULL,
    PRIMARY KEY (developer_id, phone_no),
    CONSTRAINT fk_ph_dev FOREIGN KEY (developer_id) REFERENCES developer(developer_id)
        ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- PROJECT  (manages 1:N -> manager_id)
-- ---------------------------------------------------------------------
CREATE TABLE project (
    project_id    INT AUTO_INCREMENT PRIMARY KEY,
    project_name  VARCHAR(100) NOT NULL,
    repo_url      VARCHAR(255) NOT NULL UNIQUE,
    language      VARCHAR(30)  NOT NULL,
    created_date  DATE         NOT NULL DEFAULT (CURRENT_DATE),
    manager_id    INT          NOT NULL,
    CONSTRAINT fk_proj_mgr FOREIGN KEY (manager_id) REFERENCES developer(developer_id)
        ON DELETE RESTRICT ON UPDATE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- PACKAGE
-- ---------------------------------------------------------------------
CREATE TABLE package (
    package_id      INT AUTO_INCREMENT PRIMARY KEY,
    package_name    VARCHAR(100) NOT NULL,
    ecosystem       ENUM('npm','PyPI','Maven') NOT NULL,
    latest_version  VARCHAR(20)  NOT NULL,             -- format major.minor.patch
    CONSTRAINT uq_pkg UNIQUE (package_name, ecosystem),
    CONSTRAINT chk_pkg_ver CHECK (latest_version REGEXP '^[0-9]+\\.[0-9]+\\.[0-9]+$')
) ENGINE=InnoDB;

-- uses  (M:N PROJECT - PACKAGE, attribute version_used)
CREATE TABLE project_package (
    project_id    INT         NOT NULL,
    package_id    INT         NOT NULL,
    version_used  VARCHAR(20) NOT NULL,
    PRIMARY KEY (project_id, package_id),
    CONSTRAINT chk_pp_ver CHECK (version_used REGEXP '^[0-9]+\\.[0-9]+\\.[0-9]+$'),
    CONSTRAINT fk_pp_proj FOREIGN KEY (project_id) REFERENCES project(project_id)
        ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT fk_pp_pkg  FOREIGN KEY (package_id) REFERENCES package(package_id)
        ON DELETE RESTRICT ON UPDATE CASCADE
) ENGINE=InnoDB;

-- depends_on  (recursive M:N PACKAGE - PACKAGE)
CREATE TABLE package_dependency (
    parent_id  INT NOT NULL,      -- package that needs ...
    child_id   INT NOT NULL,      -- ... this package
    PRIMARY KEY (parent_id, child_id),
    CONSTRAINT chk_no_self_dep CHECK (parent_id <> child_id),
    -- (no ON UPDATE CASCADE here: MySQL forbids it on columns used in a CHECK)
    CONSTRAINT fk_pd_parent FOREIGN KEY (parent_id) REFERENCES package(package_id)
        ON DELETE CASCADE,
    CONSTRAINT fk_pd_child  FOREIGN KEY (child_id)  REFERENCES package(package_id)
        ON DELETE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- VULNERABILITY
-- ---------------------------------------------------------------------
CREATE TABLE vulnerability (
    vuln_id         INT AUTO_INCREMENT PRIMARY KEY,
    cve_id          VARCHAR(20)  NOT NULL UNIQUE,
    severity        ENUM('LOW','MEDIUM','HIGH','CRITICAL') NOT NULL,
    published_date  DATE         NOT NULL,
    description     TEXT         NOT NULL,
    CONSTRAINT chk_cve CHECK (cve_id REGEXP '^CVE-[0-9]{4}-[0-9]{4,}$'),
    FULLTEXT KEY ft_vuln_desc (description)
) ENGINE=InnoDB;

-- affected_by  (M:N PACKAGE - VULNERABILITY, attrs affected_from / affected_to)
CREATE TABLE package_vulnerability (
    package_id     INT         NOT NULL,
    vuln_id        INT         NOT NULL,
    affected_from  VARCHAR(20) NOT NULL,
    affected_to    VARCHAR(20) NOT NULL,
    PRIMARY KEY (package_id, vuln_id),
    CONSTRAINT chk_pv_from CHECK (affected_from REGEXP '^[0-9]+\\.[0-9]+\\.[0-9]+$'),
    CONSTRAINT chk_pv_to   CHECK (affected_to   REGEXP '^[0-9]+\\.[0-9]+\\.[0-9]+$'),
    CONSTRAINT fk_pv_pkg  FOREIGN KEY (package_id) REFERENCES package(package_id)
        ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT fk_pv_vuln FOREIGN KEY (vuln_id) REFERENCES vulnerability(vuln_id)
        ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB;

-- fixed_by  (1:N VULNERABILITY - PATCH)
CREATE TABLE patch (
    patch_id       INT AUTO_INCREMENT PRIMARY KEY,
    vuln_id        INT          NOT NULL,
    fixed_version  VARCHAR(20)  NOT NULL,
    patch_date     DATE         NOT NULL,
    patch_notes    VARCHAR(255),
    CONSTRAINT chk_patch_ver CHECK (fixed_version REGEXP '^[0-9]+\\.[0-9]+\\.[0-9]+$'),
    CONSTRAINT fk_patch_vuln FOREIGN KEY (vuln_id) REFERENCES vulnerability(vuln_id)
        ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- SCAN  (WEAK entity: key = project_id + scan_no, identifying rel. "undergoes")
-- ---------------------------------------------------------------------
CREATE TABLE scan (
    project_id   INT NOT NULL,
    scan_no      INT NOT NULL,
    scan_date    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    scan_status  ENUM('running','completed','failed') NOT NULL DEFAULT 'running',
    tool_name    VARCHAR(40) NOT NULL DEFAULT 'DepScanner',
    PRIMARY KEY (project_id, scan_no),
    CONSTRAINT fk_scan_proj FOREIGN KEY (project_id) REFERENCES project(project_id)
        ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB;

-- detects  (M:N SCAN - VULNERABILITY, attr detect_status; package_id records the culprit package)
CREATE TABLE scan_vulnerability (
    project_id     INT NOT NULL,
    scan_no        INT NOT NULL,
    vuln_id        INT NOT NULL,
    package_id     INT NOT NULL,
    detect_status  ENUM('open','fixed','ignored') NOT NULL DEFAULT 'open',
    PRIMARY KEY (project_id, scan_no, vuln_id, package_id),
    CONSTRAINT fk_sv_scan FOREIGN KEY (project_id, scan_no) REFERENCES scan(project_id, scan_no)
        ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT fk_sv_vuln FOREIGN KEY (vuln_id) REFERENCES vulnerability(vuln_id)
        ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT fk_sv_pkg  FOREIGN KEY (package_id) REFERENCES package(package_id)
        ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- ALERT  (raises: SCAN 1:N ALERT, receives: DEVELOPER 1:N ALERT)
-- ---------------------------------------------------------------------
CREATE TABLE alert (
    alert_id         INT AUTO_INCREMENT PRIMARY KEY,
    project_id       INT      NOT NULL,
    scan_no          INT      NOT NULL,
    developer_id     INT      NOT NULL,
    alert_time       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    channel          ENUM('email','dashboard','slack') NOT NULL DEFAULT 'dashboard',
    is_acknowledged  BOOLEAN  NOT NULL DEFAULT FALSE,
    CONSTRAINT fk_alert_scan FOREIGN KEY (project_id, scan_no) REFERENCES scan(project_id, scan_no)
        ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT fk_alert_dev  FOREIGN KEY (developer_id) REFERENCES developer(developer_id)
        ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- AUDIT_LOG  (filled by triggers; not part of the ER diagram)
-- ---------------------------------------------------------------------
CREATE TABLE audit_log (
    log_id      INT AUTO_INCREMENT PRIMARY KEY,
    table_name  VARCHAR(40) NOT NULL,
    action      VARCHAR(20) NOT NULL,
    details     VARCHAR(255),
    logged_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- Extra indexes for the joins used most often
-- ---------------------------------------------------------------------
CREATE INDEX idx_pp_package   ON project_package(package_id);
CREATE INDEX idx_pv_vuln      ON package_vulnerability(vuln_id);
CREATE INDEX idx_vuln_sev     ON vulnerability(severity);
CREATE INDEX idx_alert_dev    ON alert(developer_id, is_acknowledged);
