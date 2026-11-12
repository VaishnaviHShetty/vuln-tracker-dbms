-- =====================================================================
-- File 5: Role-based access control INSIDE the database (GRANT / REVOKE)
-- Run as the MySQL root user in Workbench.
-- Three roles -> three login users. The web app logs in with the DB user
-- that matches the person's role, so MySQL itself blocks illegal actions.
-- =====================================================================
USE vuln_tracker;

DROP USER IF EXISTS 'tracker_admin_u'@'localhost';
DROP USER IF EXISTS 'tracker_dev_u'@'localhost';
DROP USER IF EXISTS 'tracker_viewer_u'@'localhost';
DROP ROLE IF EXISTS 'tracker_admin','tracker_developer','tracker_viewer';

CREATE ROLE 'tracker_admin','tracker_developer','tracker_viewer';

-- ---------- ADMIN: everything in this database ----------
GRANT ALL PRIVILEGES ON vuln_tracker.* TO 'tracker_admin';

-- ---------- DEVELOPER: read data, change project data, run scans ----------
-- (SELECT is granted table by table so that developer.password_hash stays hidden;
--  MySQL cannot take back one table from a schema-wide GRANT.)
GRANT SELECT ON vuln_tracker.role                  TO 'tracker_developer';
GRANT SELECT ON vuln_tracker.role_permission       TO 'tracker_developer';
GRANT SELECT ON vuln_tracker.developer_phone       TO 'tracker_developer';
GRANT SELECT ON vuln_tracker.project               TO 'tracker_developer';
GRANT SELECT ON vuln_tracker.package               TO 'tracker_developer';
GRANT SELECT ON vuln_tracker.project_package       TO 'tracker_developer';
GRANT SELECT ON vuln_tracker.package_dependency    TO 'tracker_developer';
GRANT SELECT ON vuln_tracker.package_vulnerability TO 'tracker_developer';
GRANT SELECT ON vuln_tracker.vulnerability         TO 'tracker_developer';
GRANT SELECT ON vuln_tracker.patch                 TO 'tracker_developer';
GRANT SELECT ON vuln_tracker.scan                  TO 'tracker_developer';
GRANT SELECT ON vuln_tracker.scan_vulnerability    TO 'tracker_developer';
GRANT SELECT ON vuln_tracker.alert                 TO 'tracker_developer';
GRANT SELECT ON vuln_tracker.v_project_vulnerabilities TO 'tracker_developer';
GRANT SELECT ON vuln_tracker.v_project_risk        TO 'tracker_developer';
GRANT SELECT (developer_id, first_name, last_name, email, joined_date, role_id)
      ON vuln_tracker.developer TO 'tracker_developer';

GRANT INSERT, UPDATE, DELETE ON vuln_tracker.project         TO 'tracker_developer';
GRANT INSERT, UPDATE, DELETE ON vuln_tracker.project_package TO 'tracker_developer';
GRANT INSERT, UPDATE ON vuln_tracker.scan               TO 'tracker_developer';
GRANT INSERT, UPDATE ON vuln_tracker.scan_vulnerability TO 'tracker_developer';
GRANT INSERT, UPDATE ON vuln_tracker.alert              TO 'tracker_developer';
GRANT EXECUTE ON PROCEDURE vuln_tracker.run_scan       TO 'tracker_developer';
GRANT EXECUTE ON FUNCTION  vuln_tracker.risk_score     TO 'tracker_developer';
GRANT EXECUTE ON FUNCTION  vuln_tracker.version_to_int TO 'tracker_developer';

-- ---------- VIEWER: read-only on non-sensitive tables ----------
GRANT SELECT ON vuln_tracker.project               TO 'tracker_viewer';
GRANT SELECT ON vuln_tracker.package               TO 'tracker_viewer';
GRANT SELECT ON vuln_tracker.project_package       TO 'tracker_viewer';
GRANT SELECT ON vuln_tracker.package_dependency    TO 'tracker_viewer';
GRANT SELECT ON vuln_tracker.package_vulnerability TO 'tracker_viewer';
GRANT SELECT ON vuln_tracker.vulnerability         TO 'tracker_viewer';
GRANT SELECT ON vuln_tracker.patch                 TO 'tracker_viewer';
GRANT SELECT ON vuln_tracker.scan                  TO 'tracker_viewer';
GRANT SELECT ON vuln_tracker.scan_vulnerability    TO 'tracker_viewer';
GRANT SELECT ON vuln_tracker.v_project_vulnerabilities TO 'tracker_viewer';
GRANT SELECT ON vuln_tracker.v_project_risk        TO 'tracker_viewer';
GRANT EXECUTE ON FUNCTION vuln_tracker.version_to_int TO 'tracker_viewer';
GRANT EXECUTE ON FUNCTION vuln_tracker.risk_score     TO 'tracker_viewer';

-- ---------- login users (change these passwords for your own demo) ----------
CREATE USER 'tracker_admin_u'@'localhost'  IDENTIFIED BY 'Admin@123';
CREATE USER 'tracker_dev_u'@'localhost'    IDENTIFIED BY 'Dev@12345';
CREATE USER 'tracker_viewer_u'@'localhost' IDENTIFIED BY 'View@12345';

GRANT 'tracker_admin'     TO 'tracker_admin_u'@'localhost';
GRANT 'tracker_developer' TO 'tracker_dev_u'@'localhost';
GRANT 'tracker_viewer'    TO 'tracker_viewer_u'@'localhost';

SET DEFAULT ROLE ALL TO 'tracker_admin_u'@'localhost',
                        'tracker_dev_u'@'localhost',
                        'tracker_viewer_u'@'localhost';

-- ---------- show the privileges (screenshot these for your report) ----------
SHOW GRANTS FOR 'tracker_developer';
SHOW GRANTS FOR 'tracker_viewer';

-- ---------- REVOKE demo ----------
REVOKE DELETE ON vuln_tracker.project FROM 'tracker_developer';
SHOW GRANTS FOR 'tracker_developer';
-- give it back so the web app works:
GRANT DELETE ON vuln_tracker.project TO 'tracker_developer';

-- =====================================================================
-- HOW TO DEMO: open a new Workbench connection as tracker_viewer_u, then run
--   SELECT * FROM project;                          -- works
--   DELETE FROM project WHERE project_id = 5;       -- ERROR 1142 (denied)
--   SELECT password_hash FROM developer;            -- ERROR 1142 (denied)
-- and as tracker_dev_u:
--   CALL run_scan(5, @n);                           -- works
--   DELETE FROM vulnerability;                      -- ERROR 1142 (denied)
-- =====================================================================
