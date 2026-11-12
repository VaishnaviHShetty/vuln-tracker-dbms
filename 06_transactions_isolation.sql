-- =====================================================================
-- File 6: Transactions and isolation levels (syllabus: Transaction isolation)
-- Open TWO query tabs in Workbench (Session A and Session B) and run the
-- steps in the order given.
-- =====================================================================
USE vuln_tracker;

-- ---------------- DEMO 1: non-repeatable read (READ COMMITTED) ----------------
-- [A] SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED;
-- [A] START TRANSACTION;
-- [A] SELECT version_used FROM project_package WHERE project_id=1 AND package_id=2;   -- 4.17.15
-- [B] START TRANSACTION;
-- [B] UPDATE project_package SET version_used='4.17.21' WHERE project_id=1 AND package_id=2;
-- [B] COMMIT;
-- [A] SELECT version_used FROM project_package WHERE project_id=1 AND package_id=2;   -- 4.17.21 (changed inside ONE transaction)
-- [A] COMMIT;

-- ---------------- DEMO 2: REPEATABLE READ (MySQL default) ----------------
-- First put the data back:  UPDATE project_package SET version_used='4.17.15' WHERE project_id=1 AND package_id=2;
-- [A] SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ;
-- [A] START TRANSACTION;
-- [A] SELECT version_used FROM project_package WHERE project_id=1 AND package_id=2;   -- 4.17.15
-- [B] UPDATE project_package SET version_used='4.17.21' WHERE project_id=1 AND package_id=2;  (autocommit on)
-- [A] SELECT version_used FROM project_package WHERE project_id=1 AND package_id=2;   -- still 4.17.15 (snapshot)
-- [A] COMMIT;
-- [A] SELECT version_used FROM project_package WHERE project_id=1 AND package_id=2;   -- now 4.17.21

-- ---------------- DEMO 3: locking / lost update prevention ----------------
-- [A] START TRANSACTION;
-- [A] SELECT * FROM alert WHERE alert_id=1 FOR UPDATE;        -- row locked
-- [B] UPDATE alert SET is_acknowledged=TRUE WHERE alert_id=1; -- WAITS (blocked)
-- [A] UPDATE alert SET is_acknowledged=TRUE WHERE alert_id=1;
-- [A] COMMIT;                                                 -- B continues now

-- ---------------- DEMO 4: ROLLBACK / SAVEPOINT ----------------
START TRANSACTION;
UPDATE project_package SET version_used='9.9.9' WHERE project_id=1 AND package_id=1;
SAVEPOINT after_first_change;
DELETE FROM project_package WHERE project_id=1 AND package_id=7;
ROLLBACK TO after_first_change;      -- undo only the delete
SELECT * FROM project_package WHERE project_id=1 AND package_id IN (1,7);
ROLLBACK;                            -- undo everything
SELECT * FROM project_package WHERE project_id=1 AND package_id IN (1,7);
SELECT @@transaction_isolation AS current_level;
