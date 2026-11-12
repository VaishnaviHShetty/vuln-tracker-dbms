-- =====================================================================
-- File 2: Seed data (INSERT) + DML demo (UPDATE / DELETE)
-- NOTE: CVE entries are SAMPLE data modelled on real advisories; the
-- version ranges are simplified for the project demo.
-- =====================================================================
USE vuln_tracker;

-- ---------- roles ----------
INSERT INTO role (role_name, description) VALUES
 ('admin',     'Full access: manage users, projects, vulnerabilities'),
 ('developer', 'Manage own projects, run scans, acknowledge alerts'),
 ('viewer',    'Read-only access to projects and reports');

INSERT INTO role_permission (role_id, permission) VALUES
 (1,'read'),(1,'write'),(1,'delete'),(1,'run_scan'),(1,'manage_users'),
 (2,'read'),(2,'write'),(2,'run_scan'),
 (3,'read');

-- ---------- developers (password for all demo users: password123) ----------
INSERT INTO developer (first_name,last_name,email,password_hash,joined_date,role_id) VALUES
 ('Aarav','Sharma','aarav@demo.com', SHA2('password123',256),'2024-01-10',1),
 ('Priya','Nair',  'priya@demo.com', SHA2('password123',256),'2024-02-15',2),
 ('Rohan','Mehta', 'rohan@demo.com', SHA2('password123',256),'2024-03-01',2),
 ('Sneha','Rao',   'sneha@demo.com', SHA2('password123',256),'2024-03-20',2),
 ('Kiran','Kumar', 'kiran@demo.com', SHA2('password123',256),'2024-05-05',3),
 ('Ananya','Iyer', 'ananya@demo.com',SHA2('password123',256),'2024-06-12',2);

INSERT INTO developer_phone (developer_id, phone_no) VALUES
 (1,'9876500001'),(1,'9876500011'),(2,'9876500002'),(3,'9876500003'),
 (4,'9876500004'),(4,'9876500044'),(5,'9876500005'),(6,'9876500006');

-- ---------- projects ----------
INSERT INTO project (project_name,repo_url,language,created_date,manager_id) VALUES
 ('ShopEasy',      'https://github.com/demo/shopeasy',      'JavaScript','2024-04-01',2),
 ('HealthTrack API','https://github.com/demo/healthtrack',  'Python',    '2024-04-15',3),
 ('CampusConnect', 'https://github.com/demo/campusconnect','JavaScript','2024-05-10',2),
 ('PayFlow',       'https://github.com/demo/payflow',       'Java',      '2024-06-01',4),
 ('NotesApp',      'https://github.com/demo/notesapp',      'Python',    '2024-07-01',6);

-- ---------- packages ----------
INSERT INTO package (package_name,ecosystem,latest_version) VALUES
 ('express','npm','4.19.2'),          -- 1
 ('lodash','npm','4.17.21'),          -- 2
 ('axios','npm','1.7.2'),             -- 3
 ('mongoose','npm','8.4.0'),          -- 4
 ('jsonwebtoken','npm','9.0.2'),      -- 5
 ('minimist','npm','1.2.8'),          -- 6
 ('react','npm','18.3.1'),            -- 7
 ('qs','npm','6.12.1'),               -- 8
 ('django','PyPI','5.0.6'),           -- 9
 ('flask','PyPI','3.0.3'),            -- 10
 ('requests','PyPI','2.32.3'),        -- 11
 ('pyyaml','PyPI','6.0.1'),           -- 12
 ('pillow','PyPI','10.3.0'),          -- 13
 ('log4j-core','Maven','2.23.1'),     -- 14
 ('spring-core','Maven','6.1.8'),     -- 15
 ('body-parser','npm','1.20.2'),      -- 16
 ('follow-redirects','npm','1.15.6'), -- 17
 ('urllib3','PyPI','2.2.1'),          -- 18
 ('werkzeug','PyPI','3.0.3'),         -- 19
 ('jinja2','PyPI','3.1.4'),           -- 20
 ('markupsafe','PyPI','2.1.5');       -- 21

-- ---------- uses: which project uses which package/version ----------
INSERT INTO project_package (project_id,package_id,version_used) VALUES
 -- ShopEasy
 (1,1,'4.18.2'),(1,2,'4.17.15'),(1,3,'1.4.0'),(1,4,'7.0.0'),(1,5,'8.5.1'),(1,7,'18.2.0'),(1,8,'6.10.0'),
 -- HealthTrack API
 (2,9,'4.2.0'),(2,10,'2.2.2'),(2,11,'2.28.1'),(2,12,'5.3.0'),(2,13,'8.3.0'),(2,19,'2.2.0'),
 -- CampusConnect
 (3,1,'4.17.1'),(3,2,'4.17.21'),(3,7,'18.2.0'),(3,17,'1.14.0'),(3,6,'1.2.5'),
 -- PayFlow
 (4,14,'2.14.1'),(4,15,'5.3.10'),
 -- NotesApp (clean project)
 (5,9,'5.0.6'),(5,11,'2.32.3'),(5,12,'6.0.1'),(5,13,'10.3.0');

-- ---------- depends_on: package -> package ----------
INSERT INTO package_dependency (parent_id,child_id) VALUES
 (1,16),(1,8),(16,8),      -- express -> body-parser, qs ; body-parser -> qs
 (5,2),                    -- jsonwebtoken -> lodash
 (3,17),                   -- axios -> follow-redirects
 (11,18),                  -- requests -> urllib3
 (10,19),(10,20),          -- flask -> werkzeug, jinja2
 (19,21),(20,21);          -- werkzeug, jinja2 -> markupsafe

-- ---------- vulnerabilities (SAMPLE data) ----------
INSERT INTO vulnerability (cve_id,severity,published_date,description) VALUES
 ('CVE-2021-44228','CRITICAL','2021-12-10','Remote code execution through JNDI lookup when Log4j parses attacker controlled log messages'),
 ('CVE-2020-8203', 'HIGH',    '2020-07-15','Prototype pollution in zipObjectDeep lets attackers modify object properties'),
 ('CVE-2021-44906','CRITICAL','2022-03-17','Prototype pollution in minimist through specially crafted command line arguments'),
 ('CVE-2022-23529','HIGH',    '2022-12-21','Insecure key handling in jsonwebtoken may allow remote code execution during token verification'),
 ('CVE-2022-24999','HIGH',    '2022-11-26','Prototype pollution in query string parsing allows denial of service'),
 ('CVE-2022-22965','CRITICAL','2022-04-01','Remote code execution through data binding in Spring Framework running on JDK 9 or later'),
 ('CVE-2020-1747', 'CRITICAL','2020-03-24','Arbitrary code execution when loading untrusted YAML documents with full_load'),
 ('CVE-2023-32681','MEDIUM',  '2023-05-26','Proxy authorization header leaks to the destination server after a redirect'),
 ('CVE-2022-22817','CRITICAL','2022-01-10','Arbitrary expression evaluation in ImageMath eval can lead to code execution'),
 ('CVE-2023-30861','HIGH',    '2023-05-23','Session cookie may be cached and exposed to other users when a caching proxy is used'),
 ('CVE-2023-45857','MEDIUM',  '2023-11-08','Cross site request forgery token leaks to other origins through axios requests'),
 ('CVE-2022-0155', 'MEDIUM',  '2022-01-12','Sensitive headers are exposed when a redirect goes to a different host'),
 ('CVE-2024-34069','HIGH',    '2024-05-06','Debugger allows attackers to execute code on the server when a user visits a crafted page'),
 ('CVE-2021-23337','HIGH',    '2021-02-15','Command injection through the template function in lodash'),
 ('CVE-2024-29041','MEDIUM',  '2024-03-25','Open redirect through malformed URLs in response location handling'),
 ('CVE-2021-45046','CRITICAL','2021-12-14','Incomplete fix for the Log4j JNDI issue allows code execution in some configurations');

-- ---------- affected_by: which package versions are affected ----------
INSERT INTO package_vulnerability (package_id,vuln_id,affected_from,affected_to) VALUES
 (14,1,'2.0.0','2.14.1'),
 (2, 2,'4.0.0','4.17.20'),
 (6, 3,'1.0.0','1.2.5'),
 (5, 4,'0.0.1','8.5.1'),
 (8, 5,'6.0.0','6.10.2'),
 (15,6,'5.0.0','5.3.17'),
 (12,7,'3.0.0','5.3.1'),
 (11,8,'2.0.0','2.30.0'),
 (13,9,'1.0.0','8.4.9'),
 (10,10,'2.0.0','2.2.4'),
 (3, 11,'0.8.1','1.5.9'),
 (17,12,'1.0.0','1.14.7'),
 (19,13,'0.0.1','3.0.2'),
 (2, 14,'4.0.0','4.17.20'),
 (1, 15,'4.0.0','4.19.1'),
 (14,16,'2.0.0','2.15.0');

-- ---------- fixed_by: patches ----------
INSERT INTO patch (vuln_id,fixed_version,patch_date,patch_notes) VALUES
 (1,'2.15.0','2021-12-10','JNDI lookups disabled by default'),
 (16,'2.16.0','2021-12-14','Message lookups removed completely'),
 (2,'4.17.21','2021-02-20','Input validation added to zipObjectDeep'),
 (14,'4.17.21','2021-02-20','Template option sanitised'),
 (3,'1.2.6','2022-03-18','Blocks prototype keys'),
 (4,'9.0.0','2022-12-21','Stricter key type checks'),
 (5,'6.10.3','2022-11-27','Safer query parsing'),
 (6,'5.3.18','2022-03-31','Data binding restricted'),
 (7,'5.4.0','2020-03-30','full_load now safe by default'),
 (8,'2.31.0','2023-05-22','Proxy headers stripped on redirect'),
 (9,'9.0.0','2022-01-02','ImageMath.eval restricted'),
 (10,'2.2.5','2023-05-02','Vary: Cookie header added'),
 (11,'1.6.0','2023-10-26','Token only sent to same origin'),
 (12,'1.14.8','2022-01-10','Sensitive headers dropped on cross host redirect'),
 (13,'3.0.3','2024-05-07','Debugger host check fixed'),
 (15,'4.19.2','2024-03-25','URL encoding fixed');

-- =====================================================================
-- DML DEMO  (UPDATE / DELETE / INSERT with checks)  -- rubric: DML (4)
-- =====================================================================
-- UPDATE: a project is upgraded to a newer lodash version
UPDATE project_package SET version_used = '4.17.21' WHERE project_id = 1 AND package_id = 2;

-- UPDATE: change a developer's role (promote Sneha to admin)
UPDATE developer SET role_id = (SELECT role_id FROM role WHERE role_name='admin')
WHERE email = 'sneha@demo.com';
-- ... and revert it so the rest of the demo data stays as designed
UPDATE developer SET role_id = (SELECT role_id FROM role WHERE role_name='developer')
WHERE email = 'sneha@demo.com';

-- INSERT: add a new developer + phone, then DELETE them (cascade removes the phone)
INSERT INTO developer (first_name,last_name,email,password_hash,role_id)
VALUES ('Temp','User','temp@demo.com',SHA2('password123',256),3);
INSERT INTO developer_phone (developer_id,phone_no)
VALUES ((SELECT developer_id FROM developer WHERE email='temp@demo.com'),'9000000000');
DELETE FROM developer WHERE email = 'temp@demo.com';

-- Put ShopEasy back on the vulnerable lodash version so scans have findings to show
UPDATE project_package SET version_used = '4.17.15' WHERE project_id = 1 AND package_id = 2;

-- Quick sanity counts
SELECT 'developers' t, COUNT(*) n FROM developer UNION ALL
SELECT 'projects',     COUNT(*) FROM project   UNION ALL
SELECT 'packages',     COUNT(*) FROM package   UNION ALL
SELECT 'vulns',        COUNT(*) FROM vulnerability;
