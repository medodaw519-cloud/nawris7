CREATE TABLE IF NOT EXISTS package_logs (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    package_id BIGINT UNSIGNED NOT NULL,
    employee_id BIGINT UNSIGNED NOT NULL,
    employee_name VARCHAR(255) NOT NULL,
    action_type VARCHAR(50) NOT NULL,
    status VARCHAR(50) NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_package_logs_package_date (package_id, created_at),
    INDEX idx_package_logs_date (created_at),
    INDEX idx_package_logs_employee_date (employee_id, created_at)
);
