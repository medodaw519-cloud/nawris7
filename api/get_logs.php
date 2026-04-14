<?php
declare(strict_types=1);

require __DIR__ . '/db.php';

if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    json_response(['success' => false, 'message' => 'Method not allowed'], 405);
}

$date = trim((string)($_GET['date'] ?? ''));
if ($date === '') {
    $date = date('Y-m-d');
}

$isValidDate = (bool)preg_match('/^\d{4}-\d{2}-\d{2}$/', $date);
if (!$isValidDate) {
    json_response(['success' => false, 'message' => 'Invalid date format. Use YYYY-MM-DD'], 400);
}

$packageRaw = trim((string)($_GET['package_id'] ?? ''));
$packageId = preg_replace('/[^0-9]/', '', $packageRaw);

try {
    $pdo = crm_pdo();

    if ($packageId !== '') {
        $stmt = $pdo->prepare(
            'SELECT id, package_id, employee_id, employee_name, action_type, status, created_at
             FROM package_logs
             WHERE package_id = :package_id
               AND DATE(created_at) = :date
             ORDER BY created_at DESC'
        );
        $stmt->execute([
            ':package_id' => $packageId,
            ':date' => $date,
        ]);
    } else {
        $stmt = $pdo->prepare(
            'SELECT id, package_id, employee_id, employee_name, action_type, status, created_at
             FROM package_logs
             WHERE DATE(created_at) = :date
             ORDER BY created_at DESC'
        );
        $stmt->execute([':date' => $date]);
    }

    $logs = $stmt->fetchAll();

    json_response([
        'success' => true,
        'date' => $date,
        'count' => count($logs),
        'logs' => $logs,
    ], 200);
} catch (Throwable $e) {
    json_response([
        'success' => false,
        'message' => 'Failed to fetch logs',
        'error' => $e->getMessage(),
    ], 500);
}
