-- =====================================================================
-- File 3: Functions, Stored Procedure, Triggers, Views
-- Run the WHOLE file in MySQL Workbench (it uses DELIMITER $$)
-- =====================================================================
USE vuln_tracker;

DROP FUNCTION  IF EXISTS version_to_int;
DROP FUNCTION  IF EXISTS risk_score;
DROP PROCEDURE IF EXISTS run_scan;
DROP TRIGGER   IF EXISTS trg_pv_validate;
DROP TRIGGER   IF EXISTS trg_pv_audit;
DROP TRIGGER   IF EXISTS trg_vuln_audit;
DROP TRIGGER   IF EXISTS trg_sv_status_audit;
DROP VIEW      IF EXISTS v_project_vulnerabilities;
DROP VIEW      IF EXISTS v_project_risk;

DELIMITER $$

-- ---------------------------------------------------------------------
-- FUNCTION 1: turn '4.17.15' into 4017015 so versions compare correctly
-- (plain string compare would say '4.9.0' > '4.17.0', which is wrong)
-- ---------------------------------------------------------------------
CREATE FUNCTION version_to_int(v VARCHAR(20)) RETURNS BIGINT
DETERMINISTIC NO SQL
BEGIN
    RETURN CAST(SUBSTRING_INDEX(v, '.', 1) AS UNSIGNED) * 1000000
         + CAST(SUBSTRING_INDEX(SUBSTRING_INDEX(v, '.', 2), '.', -1) AS UNSIGNED) * 1000
         + CAST(SUBSTRING_INDEX(v, '.', -1) AS UNSIGNED);
END$$

-- ---------------------------------------------------------------------
-- FUNCTION 2: risk score of a project
-- Each distinct vulnerability found in the project's dependencies adds
-- CRITICAL=10, HIGH=7, MEDIUM=4, LOW=1
-- ---------------------------------------------------------------------
CREATE FUNCTION risk_score(p_project_id INT) RETURNS INT
READS SQL DATA
BEGIN
    DECLARE score INT;
    SELECT COALESCE(SUM(CASE x.severity
                          WHEN 'CRITICAL' THEN 10
                          WHEN 'HIGH'     THEN 7
                          WHEN 'MEDIUM'   THEN 4
                          ELSE 1 END), 0)
      INTO score
      FROM (SELECT DISTINCT v.vuln_id, v.severity
              FROM project_package pp
              JOIN package_vulnerability pv ON pv.package_id = pp.package_id
              JOIN vulnerability v          ON v.vuln_id     = pv.vuln_id
             WHERE pp.project_id = p_project_id
               AND version_to_int(pp.version_used)
                   BETWEEN version_to_int(pv.affected_from) AND version_to_int(pv.affected_to)) x;
    RETURN score;
END$$

-- ---------------------------------------------------------------------
-- PROCEDURE: run_scan
-- Creates the next scan for a project, compares every dependency version
-- with the vulnerability database, stores findings and alerts the manager.
-- Everything is one transaction: either the whole scan is saved or nothing.
-- ---------------------------------------------------------------------
CREATE PROCEDURE run_scan(IN p_project_id INT, OUT p_findings INT)
BEGIN
    DECLARE v_scan_no INT;
    DECLARE v_manager INT;

    DECLARE EXIT HANDLER FOR SQLEXCEPTION
    BEGIN
        ROLLBACK;
        RESIGNAL;
    END;

    IF NOT EXISTS (SELECT 1 FROM project WHERE project_id = p_project_id) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Project does not exist';
    END IF;

    START TRANSACTION;

    -- weak entity: scan_no restarts at 1 for every project
    SELECT COALESCE(MAX(scan_no), 0) + 1 INTO v_scan_no
      FROM scan WHERE project_id = p_project_id FOR UPDATE;

    INSERT INTO scan (project_id, scan_no, scan_status)
    VALUES (p_project_id, v_scan_no, 'running');

    INSERT INTO scan_vulnerability (project_id, scan_no, vuln_id, package_id)
    SELECT DISTINCT p_project_id, v_scan_no, pv.vuln_id, pp.package_id
      FROM project_package pp
      JOIN package_vulnerability pv ON pv.package_id = pp.package_id
     WHERE pp.project_id = p_project_id
       AND version_to_int(pp.version_used)
           BETWEEN version_to_int(pv.affected_from) AND version_to_int(pv.affected_to);

    SET p_findings = ROW_COUNT();

    IF p_findings > 0 THEN
        SELECT manager_id INTO v_manager FROM project WHERE project_id = p_project_id;
        INSERT INTO alert (project_id, scan_no, developer_id, channel)
        VALUES (p_project_id, v_scan_no, v_manager, 'dashboard');
    END IF;

    UPDATE scan SET scan_status = 'completed'
     WHERE project_id = p_project_id AND scan_no = v_scan_no;

    COMMIT;
END$$

-- ---------------------------------------------------------------------
-- TRIGGER 1 (BEFORE INSERT): reject a version range where from > to
-- ---------------------------------------------------------------------
CREATE TRIGGER trg_pv_validate
BEFORE INSERT ON package_vulnerability
FOR EACH ROW
BEGIN
    IF version_to_int(NEW.affected_from) > version_to_int(NEW.affected_to) THEN
        SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = 'affected_from must not be greater than affected_to';
    END IF;
END$$

-- ---------------------------------------------------------------------
-- TRIGGER 2 (AFTER INSERT): audit when a vulnerability is linked to a package
-- ---------------------------------------------------------------------
CREATE TRIGGER trg_pv_audit
AFTER INSERT ON package_vulnerability
FOR EACH ROW
BEGIN
    INSERT INTO audit_log (table_name, action, details)
    VALUES ('package_vulnerability', 'INSERT',
            CONCAT('Vuln ', NEW.vuln_id, ' linked to package ', NEW.package_id,
                   ' (', NEW.affected_from, ' - ', NEW.affected_to, ')'));
END$$

-- ---------------------------------------------------------------------
-- TRIGGER 3 (AFTER INSERT): audit every new CVE
-- ---------------------------------------------------------------------
CREATE TRIGGER trg_vuln_audit
AFTER INSERT ON vulnerability
FOR EACH ROW
BEGIN
    INSERT INTO audit_log (table_name, action, details)
    VALUES ('vulnerability', 'INSERT',
            CONCAT('New ', NEW.severity, ' vulnerability ', NEW.cve_id));
END$$

-- ---------------------------------------------------------------------
-- TRIGGER 4 (AFTER UPDATE): audit a finding when its status changes
-- ---------------------------------------------------------------------
CREATE TRIGGER trg_sv_status_audit
AFTER UPDATE ON scan_vulnerability
FOR EACH ROW
BEGIN
    IF OLD.detect_status <> NEW.detect_status THEN
        INSERT INTO audit_log (table_name, action, details)
        VALUES ('scan_vulnerability', 'UPDATE',
                CONCAT('Project ', NEW.project_id, ' scan ', NEW.scan_no, ' vuln ', NEW.vuln_id,
                       ': ', OLD.detect_status, ' -> ', NEW.detect_status));
    END IF;
END$$

DELIMITER ;

-- ---------------------------------------------------------------------
-- VIEW 1: every vulnerable dependency of every project (live, no scan needed)
-- ---------------------------------------------------------------------
CREATE VIEW v_project_vulnerabilities AS
SELECT p.project_id, p.project_name, pk.package_id, pk.package_name, pp.version_used,
       v.vuln_id, v.cve_id, v.severity,
       pv.affected_from, pv.affected_to,
       (SELECT MIN(pt.fixed_version) FROM patch pt WHERE pt.vuln_id = v.vuln_id) AS fix_version
  FROM project p
  JOIN project_package pp         ON pp.project_id = p.project_id
  JOIN package pk                 ON pk.package_id = pp.package_id
  JOIN package_vulnerability pv   ON pv.package_id = pk.package_id
  JOIN vulnerability v            ON v.vuln_id     = pv.vuln_id
 WHERE version_to_int(pp.version_used)
       BETWEEN version_to_int(pv.affected_from) AND version_to_int(pv.affected_to);

-- ---------------------------------------------------------------------
-- VIEW 2: project risk summary (uses the function)
-- ---------------------------------------------------------------------
CREATE VIEW v_project_risk AS
SELECT p.project_id, p.project_name, p.language,
       CONCAT(d.first_name, ' ', d.last_name) AS manager,
       risk_score(p.project_id) AS risk_score
  FROM project p
  JOIN developer d ON d.developer_id = p.manager_id;
