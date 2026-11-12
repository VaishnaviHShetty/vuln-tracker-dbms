-- =====================================================================
-- File 4: Queries  (run ONE query at a time: select it, press Ctrl+Enter)
-- Covers: joins, outer join, nested, correlated, aggregate, set ops,
--         window functions, recursive CTE, full-text search, views,
--         function / procedure / trigger demos
-- =====================================================================
USE vuln_tracker;

-- Q1  INNER JOIN (4 tables): which project uses which vulnerable package version
SELECT p.project_name, pk.package_name, pp.version_used, v.cve_id, v.severity
  FROM project p
  JOIN project_package pp       ON pp.project_id = p.project_id
  JOIN package pk               ON pk.package_id = pp.package_id
  JOIN package_vulnerability pv ON pv.package_id = pk.package_id
  JOIN vulnerability v          ON v.vuln_id     = pv.vuln_id
 WHERE version_to_int(pp.version_used)
       BETWEEN version_to_int(pv.affected_from) AND version_to_int(pv.affected_to)
 ORDER BY p.project_name, v.severity;

-- Q2  LEFT OUTER JOIN: packages that have NO known vulnerability
SELECT pk.package_name, pk.ecosystem
  FROM package pk
  LEFT JOIN package_vulnerability pv ON pv.package_id = pk.package_id
 WHERE pv.vuln_id IS NULL;

-- Q3  NESTED (uncorrelated) subquery: projects that use a package having a CRITICAL vulnerability
SELECT project_name
  FROM project
 WHERE project_id IN (
        SELECT pp.project_id
          FROM project_package pp
         WHERE pp.package_id IN (
                SELECT pv.package_id
                  FROM package_vulnerability pv
                  JOIN vulnerability v ON v.vuln_id = pv.vuln_id
                 WHERE v.severity = 'CRITICAL'));

-- Q4  CORRELATED subquery: packages with MORE vulnerabilities than the average package
SELECT pk.package_name,
       (SELECT COUNT(*) FROM package_vulnerability pv
         WHERE pv.package_id = pk.package_id) AS vuln_count
  FROM package pk
 WHERE (SELECT COUNT(*) FROM package_vulnerability pv
         WHERE pv.package_id = pk.package_id)
       > (SELECT AVG(c) FROM (SELECT COUNT(*) AS c
                                FROM package_vulnerability
                               GROUP BY package_id) t);

-- Q5  CORRELATED EXISTS: developers who manage at least one project with risk score above 30
SELECT d.first_name, d.last_name
  FROM developer d
 WHERE EXISTS (SELECT 1 FROM project p
                WHERE p.manager_id = d.developer_id
                  AND risk_score(p.project_id) > 30);

-- Q6  GROUP BY + HAVING: number of vulnerabilities per ecosystem and severity
SELECT pk.ecosystem, v.severity, COUNT(DISTINCT v.vuln_id) AS total
  FROM package pk
  JOIN package_vulnerability pv ON pv.package_id = pk.package_id
  JOIN vulnerability v          ON v.vuln_id     = pv.vuln_id
 GROUP BY pk.ecosystem, v.severity
HAVING total >= 1
 ORDER BY pk.ecosystem, v.severity;

-- Q7  SET OPERATION (UNION): packages that are either Maven packages or have a CRITICAL vulnerability
SELECT package_name FROM package WHERE ecosystem = 'Maven'
UNION
SELECT pk.package_name
  FROM package pk
  JOIN package_vulnerability pv ON pv.package_id = pk.package_id
  JOIN vulnerability v          ON v.vuln_id = pv.vuln_id
 WHERE v.severity = 'CRITICAL';

-- Q8  WINDOW FUNCTIONS: rank projects by risk (RANK, DENSE_RANK, running total)
SELECT project_name, risk_score,
       RANK()       OVER (ORDER BY risk_score DESC) AS risk_rank,
       DENSE_RANK() OVER (ORDER BY risk_score DESC) AS dense_rank_no,
       SUM(risk_score) OVER (ORDER BY risk_score DESC
                             ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) AS running_total
  FROM v_project_risk;

-- Q8b WINDOW FUNCTION with PARTITION: most severe finding per project
SELECT project_name, cve_id, severity
  FROM (SELECT project_name, cve_id, severity,
               ROW_NUMBER() OVER (PARTITION BY project_id
                                  ORDER BY FIELD(severity,'CRITICAL','HIGH','MEDIUM','LOW')) AS rn
          FROM v_project_vulnerabilities) t
 WHERE rn = 1;

-- Q9  RECURSIVE CTE: full (transitive) dependency tree of the package 'express'
WITH RECURSIVE dep_tree AS (
    SELECT pd.parent_id, pd.child_id, 1 AS depth,
           CAST(CONCAT(p.package_name, ' -> ', c.package_name) AS CHAR(300)) AS path
      FROM package_dependency pd
      JOIN package p ON p.package_id = pd.parent_id
      JOIN package c ON c.package_id = pd.child_id
     WHERE p.package_name = 'express'
    UNION ALL
    SELECT pd.parent_id, pd.child_id, t.depth + 1,
           CONCAT(t.path, ' -> ', c.package_name)
      FROM dep_tree t
      JOIN package_dependency pd ON pd.parent_id = t.child_id
      JOIN package c             ON c.package_id = pd.child_id
)
SELECT depth, path FROM dep_tree ORDER BY depth, path;

-- Q9b RECURSIVE CTE: every package a project depends on, directly or indirectly
WITH RECURSIVE all_deps AS (
    SELECT package_id, 0 AS depth FROM project_package WHERE project_id = 1
    UNION
    SELECT pd.child_id, a.depth + 1
      FROM all_deps a
      JOIN package_dependency pd ON pd.parent_id = a.package_id
)
SELECT pk.package_name, MIN(a.depth) AS depth,
       IF(MIN(a.depth) = 0, 'direct', 'transitive') AS kind
  FROM all_deps a
  JOIN package pk ON pk.package_id = a.package_id
 GROUP BY pk.package_name
 ORDER BY depth, pk.package_name;

-- Q10 FULL-TEXT SEARCH: find vulnerabilities by words in the description
SELECT cve_id, severity,
       MATCH(description) AGAINST ('code execution' IN NATURAL LANGUAGE MODE) AS relevance
  FROM vulnerability
 WHERE MATCH(description) AGAINST ('code execution' IN NATURAL LANGUAGE MODE)
 ORDER BY relevance DESC;

-- Q10b FULL-TEXT, boolean mode: must contain "prototype", must not contain "denial"
SELECT cve_id, description
  FROM vulnerability
 WHERE MATCH(description) AGAINST ('+prototype -denial' IN BOOLEAN MODE);

-- Q11 VIEWS
SELECT * FROM v_project_vulnerabilities WHERE severity = 'CRITICAL';
SELECT * FROM v_project_risk ORDER BY risk_score DESC;

-- Q12 FUNCTION demo
SELECT version_to_int('4.9.0') < version_to_int('4.17.0') AS correct_compare,
       '4.9.0' < '4.17.0'                                  AS wrong_string_compare;
SELECT project_name, risk_score(project_id) AS score FROM project;

-- Q13 PROCEDURE demo: scan every project, then read the results
CALL run_scan(1, @n);  SELECT @n AS findings_project1;
CALL run_scan(2, @n);  SELECT @n AS findings_project2;
CALL run_scan(3, @n);  SELECT @n AS findings_project3;
CALL run_scan(4, @n);  SELECT @n AS findings_project4;
SELECT s.project_id, s.scan_no, s.scan_status, COUNT(sv.vuln_id) AS findings
  FROM scan s
  LEFT JOIN scan_vulnerability sv ON sv.project_id = s.project_id AND sv.scan_no = s.scan_no
 GROUP BY s.project_id, s.scan_no, s.scan_status;
SELECT a.alert_id, p.project_name, CONCAT(d.first_name,' ',d.last_name) AS sent_to, a.is_acknowledged
  FROM alert a
  JOIN project p   ON p.project_id = a.project_id
  JOIN developer d ON d.developer_id = a.developer_id;

-- Q14 TRIGGER demos
-- (a) valid insert -> trigger writes to audit_log
INSERT INTO vulnerability (cve_id,severity,published_date,description)
VALUES ('CVE-2025-0001','HIGH','2025-01-15','Sample demo vulnerability for the trigger test');
SELECT * FROM audit_log ORDER BY log_id DESC;
-- (b) invalid range -> trigger rejects it (this statement is EXPECTED to fail)
INSERT INTO package_vulnerability (package_id,vuln_id,affected_from,affected_to)
VALUES (7, (SELECT vuln_id FROM vulnerability WHERE cve_id='CVE-2025-0001'), '5.0.0', '2.0.0');
-- (c) status change on a finding -> audit trigger
UPDATE scan_vulnerability SET detect_status = 'fixed'
 WHERE project_id = 1 AND scan_no = 1 AND vuln_id = 2 AND package_id = 2;
SELECT * FROM audit_log ORDER BY log_id DESC LIMIT 3;
