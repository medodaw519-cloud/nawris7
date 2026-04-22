<?php
declare(strict_types=1);

require __DIR__ . '/db.php';

/**
 * POST delete action is allowed only for "مدير نظام".
 * The check supports role fields and permission lists in session.
 */
function has_system_manager_access(array $session): bool
{
    $managerLabels = ['مدير نظام', 'system_manager'];

    $roleFields = ['role', 'employee_role', 'user_role', 'job_title'];
    foreach ($roleFields as $field) {
        $value = trim((string)($session[$field] ?? ''));
        if ($value !== '' && in_array($value, $managerLabels, true)) {
            return true;
        }
    }

    $permissionFields = ['permissions', 'perms', 'user_permissions', 'roles'];
    foreach ($permissionFields as $field) {
        $raw = $session[$field] ?? null;
        $values = [];

        if (is_array($raw)) {
            $values = $raw;
        } elseif (is_string($raw) && trim($raw) !== '') {
            $decoded = json_decode($raw, true);
            if (is_array($decoded)) {
                $values = $decoded;
            } else {
                $values = preg_split('/[\s,|;]+/u', $raw) ?: [];
            }
        }

        foreach ($values as $item) {
            $v = trim((string)$item);
            if ($v !== '' && in_array($v, $managerLabels, true)) {
                return true;
            }
        }
    }

    return false;
}

if (!in_array($_SERVER['REQUEST_METHOD'] ?? 'GET', ['GET', 'POST'], true)) {
    json_response(['success' => false, 'message' => 'Method not allowed'], 405);
}

session_start();

/**
 * Allow only authenticated backoffice sessions.
 * This prevents accidental or public deletion calls.
 */
$employeeId = $_SESSION['employee_id'] ?? null;
$employeeName = $_SESSION['employee_name'] ?? null;
if (!$employeeId || !$employeeName) {
    json_response(['success' => false, 'message' => 'Unauthorized session'], 401);
}

/**
 * Optional extra protection via secret key:
 * set CLEANUP_API_KEY in environment and pass it in request as cleanup_key.
 */
$configuredCleanupKey = (string)(getenv('CLEANUP_API_KEY') ?: '');
$requestCleanupKey = trim((string)($_GET['cleanup_key'] ?? ''));

if ($configuredCleanupKey !== '' && !hash_equals($configuredCleanupKey, $requestCleanupKey)) {
    json_response([
        'success' => false,
        'message' => 'Invalid cleanup_key',
    ], 403);
}

$table = trim((string)($_GET['table'] ?? 'shipments'));
if ($table === '' || !preg_match('/^[a-zA-Z0-9_]+$/', $table)) {
    json_response(['success' => false, 'message' => 'Invalid table name'], 400);
}

$limitRaw = (int)($_GET['limit'] ?? 500);
$limit = max(1, min($limitRaw, 5000));
$includeTerminal = (string)($_GET['include_terminal'] ?? '0') === '1';

try {
    $pdo = crm_pdo();

    $tableExistsStmt = $pdo->prepare(
        'SELECT COUNT(*) AS c
         FROM information_schema.tables
         WHERE table_schema = DATABASE() AND table_name = :table_name'
    );
    $tableExistsStmt->execute([':table_name' => $table]);
    $tableExists = (int)$tableExistsStmt->fetchColumn() > 0;
    if (!$tableExists) {
        json_response(['success' => false, 'message' => 'Table not found'], 404);
    }

    $columnsStmt = $pdo->prepare(
        'SELECT column_name
         FROM information_schema.columns
         WHERE table_schema = DATABASE() AND table_name = :table_name'
    );
    $columnsStmt->execute([':table_name' => $table]);
    $columns = array_map(
        static fn (array $row): string => (string)$row['column_name'],
        $columnsStmt->fetchAll()
    );
    $columnsMap = array_fill_keys($columns, true);

    if (!isset($columnsMap['id'])) {
        json_response([
            'success' => false,
            'message' => 'Safety check failed: table must have an id column.',
        ], 422);
    }

    if (!isset($columnsMap['api_source']) || !isset($columnsMap['external_id'])) {
        json_response([
            'success' => false,
            'message' => 'Safety check failed: target table must contain both api_source and external_id columns.',
        ], 422);
    }

    // Deletion target: rows that were not created via API.
    $whereSql = '((api_source IS NULL OR TRIM(api_source) = \'\') OR (external_id IS NULL OR TRIM(external_id) = \'\'))';

    // Protect essential operational records unless explicitly requested.
    if (!$includeTerminal && isset($columnsMap['status'])) {
        $whereSql .= ' AND status NOT IN (\'delivered\', \'completed\', \'returned\', \'canceled\')';
    }

    $countSql = "SELECT COUNT(*) FROM `{$table}` WHERE {$whereSql}";
    $count = (int)$pdo->query($countSql)->fetchColumn();

    $sampleSql = "SELECT id FROM `{$table}` WHERE {$whereSql} ORDER BY id ASC LIMIT 20";
    $sampleIds = array_map(
        static fn (array $row): int => (int)$row['id'],
        $pdo->query($sampleSql)->fetchAll()
    );

    // GET = preview only.
    if ($_SERVER['REQUEST_METHOD'] === 'GET') {
        json_response([
            'success' => true,
            'mode' => 'preview',
            'table' => $table,
            'candidate_count' => $count,
            'sample_ids' => $sampleIds,
            'delete_limit' => $limit,
            'include_terminal' => $includeTerminal,
            'message' => 'Preview only. Use POST with confirm=DELETE_NON_API_SHIPMENTS to execute.',
        ], 200);
    }

    if (!has_system_manager_access($_SESSION)) {
        json_response([
            'success' => false,
            'message' => 'POST is restricted to users with مدير نظام permission.',
        ], 403);
    }

    $rawBody = file_get_contents('php://input');
    $payload = json_decode($rawBody ?: '{}', true);
    if (!is_array($payload)) {
        json_response(['success' => false, 'message' => 'Invalid JSON body'], 400);
    }

    $confirm = trim((string)($payload['confirm'] ?? ''));
    if ($confirm !== 'DELETE_NON_API_SHIPMENTS') {
        json_response([
            'success' => false,
            'message' => 'Confirmation phrase is required.',
            'required_confirm' => 'DELETE_NON_API_SHIPMENTS',
        ], 400);
    }

    if ($count === 0) {
        json_response([
            'success' => true,
            'mode' => 'execute',
            'table' => $table,
            'deleted_count' => 0,
            'message' => 'No matching records to delete.',
        ], 200);
    }

    $pdo->beginTransaction();

    $backupTableSql = 'CREATE TABLE IF NOT EXISTS shipments_cleanup_backup (
        id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        table_name VARCHAR(120) NOT NULL,
        record_id BIGINT UNSIGNED NOT NULL,
        payload LONGTEXT NOT NULL,
        reason VARCHAR(255) NOT NULL,
        deleted_by_employee_id BIGINT UNSIGNED NOT NULL,
        deleted_by_employee_name VARCHAR(255) NOT NULL,
        deleted_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_cleanup_table_record (table_name, record_id),
        INDEX idx_cleanup_deleted_at (deleted_at)
    )';
    $pdo->exec($backupTableSql);

    $selectRowsSql = "SELECT * FROM `{$table}` WHERE {$whereSql} ORDER BY id ASC LIMIT :limit_rows";
    $selectRowsStmt = $pdo->prepare($selectRowsSql);
    $selectRowsStmt->bindValue(':limit_rows', $limit, PDO::PARAM_INT);
    $selectRowsStmt->execute();
    $rowsToDelete = $selectRowsStmt->fetchAll();

    if ($rowsToDelete === []) {
        $pdo->rollBack();
        json_response([
            'success' => true,
            'mode' => 'execute',
            'table' => $table,
            'deleted_count' => 0,
            'message' => 'No records selected for this limit.',
        ], 200);
    }

    $backupStmt = $pdo->prepare(
        'INSERT INTO shipments_cleanup_backup
        (table_name, record_id, payload, reason, deleted_by_employee_id, deleted_by_employee_name)
        VALUES (:table_name, :record_id, :payload, :reason, :deleted_by_employee_id, :deleted_by_employee_name)'
    );

    $ids = [];
    $backupsInserted = 0;
    foreach ($rowsToDelete as $row) {
        $recordId = (int)($row['id'] ?? 0);
        if ($recordId <= 0) {
            continue;
        }

        $ids[] = $recordId;
        $backupStmt->execute([
            ':table_name' => $table,
            ':record_id' => $recordId,
            ':payload' => json_encode($row, JSON_UNESCAPED_UNICODE),
            ':reason' => 'cleanup_non_api_rows',
            ':deleted_by_employee_id' => (int)$employeeId,
            ':deleted_by_employee_name' => (string)$employeeName,
        ]);
        if ($backupStmt->rowCount() !== 1) {
            throw new RuntimeException('Backup insert failed for record id: ' . $recordId);
        }
        $backupsInserted++;
    }

    if ($ids === []) {
        $pdo->rollBack();
        json_response([
            'success' => false,
            'message' => 'Safety check failed: no valid IDs selected for deletion.',
        ], 422);
    }

    if ($backupsInserted !== count($ids)) {
        $pdo->rollBack();
        json_response([
            'success' => false,
            'message' => 'Safety check failed: backup count mismatch. Delete aborted.',
            'backup_inserted' => $backupsInserted,
            'selected_ids' => count($ids),
        ], 422);
    }

    $placeholders = implode(',', array_fill(0, count($ids), '?'));
    $deleteSql = "DELETE FROM `{$table}` WHERE id IN ({$placeholders})";
    $deleteStmt = $pdo->prepare($deleteSql);
    $deleteStmt->execute($ids);

    $deleted = $deleteStmt->rowCount();
    $pdo->commit();

    json_response([
        'success' => true,
        'mode' => 'execute',
        'table' => $table,
        'deleted_count' => $deleted,
        'backup_inserted' => $backupsInserted,
        'requested_limit' => $limit,
        'candidate_count_before_delete' => $count,
        'message' => 'Cleanup completed. Backup saved to shipments_cleanup_backup.',
    ], 200);
} catch (Throwable $e) {
    if (isset($pdo) && $pdo instanceof PDO && $pdo->inTransaction()) {
        $pdo->rollBack();
    }

    json_response([
        'success' => false,
        'message' => 'Cleanup failed',
        'error' => $e->getMessage(),
    ], 500);
}

