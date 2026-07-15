-- CreateTable
CREATE TABLE "users" (
    "user_id" SERIAL NOT NULL,
    "username" TEXT NOT NULL,
    "display_name" TEXT NOT NULL,
    "password_hash" TEXT NOT NULL,
    "role" TEXT NOT NULL DEFAULT 'admin',
    "is_active" TEXT NOT NULL DEFAULT 'Y',
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "users_pkey" PRIMARY KEY ("user_id")
);

-- CreateTable
CREATE TABLE "devices" (
    "device_id" SERIAL NOT NULL,
    "mac_address" TEXT NOT NULL,
    "ip_address" TEXT NOT NULL,
    "hostname" TEXT,
    "vendor" TEXT,
    "device_type" TEXT,
    "os_name" TEXT,
    "os_version" TEXT,
    "firmware_version" TEXT,
    "open_ports" TEXT,
    "services" TEXT,
    "is_active" TEXT NOT NULL DEFAULT 'Y',
    "first_seen" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "last_seen" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "devices_pkey" PRIMARY KEY ("device_id")
);

-- CreateTable
CREATE TABLE "vulnerabilities" (
    "vuln_id" SERIAL NOT NULL,
    "cve_id" TEXT NOT NULL,
    "cvss_score" DOUBLE PRECISION,
    "severity" TEXT,
    "description" TEXT,
    "affected_cpe" TEXT,
    "remediation" TEXT,
    "published_date" TIMESTAMP(3),
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "vulnerabilities_pkey" PRIMARY KEY ("vuln_id")
);

-- CreateTable
CREATE TABLE "scan_jobs" (
    "scan_id" SERIAL NOT NULL,
    "user_id" INTEGER,
    "scan_type" TEXT NOT NULL DEFAULT 'full',
    "status" TEXT NOT NULL DEFAULT 'pending',
    "progress" INTEGER NOT NULL DEFAULT 0,
    "device_count" INTEGER NOT NULL DEFAULT 0,
    "error_log" TEXT,
    "started_at" TIMESTAMP(3),
    "completed_at" TIMESTAMP(3),
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "scan_jobs_pkey" PRIMARY KEY ("scan_id")
);

-- CreateTable
CREATE TABLE "scan_results" (
    "result_id" SERIAL NOT NULL,
    "scan_id" INTEGER NOT NULL,
    "device_id" INTEGER NOT NULL,
    "port" INTEGER,
    "protocol" TEXT,
    "service" TEXT,
    "banner" TEXT,
    "risk_level" TEXT,
    "vuln_id" INTEGER,
    "detail" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "scan_results_pkey" PRIMARY KEY ("result_id")
);

-- CreateTable
CREATE TABLE "risk_assessments" (
    "assessment_id" SERIAL NOT NULL,
    "device_id" INTEGER NOT NULL,
    "scan_id" INTEGER NOT NULL,
    "composite_score" DOUBLE PRECISION NOT NULL,
    "cve_score" DOUBLE PRECISION NOT NULL,
    "exposure_score" DOUBLE PRECISION NOT NULL,
    "credential_score" DOUBLE PRECISION NOT NULL,
    "network_score" DOUBLE PRECISION NOT NULL,
    "recommendation" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "risk_assessments_pkey" PRIMARY KEY ("assessment_id")
);

-- CreateTable
CREATE TABLE "alert_rules" (
    "rule_id" SERIAL NOT NULL,
    "name" TEXT NOT NULL,
    "event_type" TEXT NOT NULL,
    "threshold" DOUBLE PRECISION,
    "channels" TEXT,
    "enabled" TEXT NOT NULL DEFAULT 'Y',
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "alert_rules_pkey" PRIMARY KEY ("rule_id")
);

-- CreateTable
CREATE TABLE "notifications" (
    "notif_id" SERIAL NOT NULL,
    "rule_id" INTEGER,
    "device_id" INTEGER,
    "message" TEXT NOT NULL,
    "severity" TEXT,
    "is_read" TEXT NOT NULL DEFAULT 'N',
    "sent_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "notifications_pkey" PRIMARY KEY ("notif_id")
);

-- CreateIndex
CREATE UNIQUE INDEX "users_username_key" ON "users"("username");

-- CreateIndex
CREATE UNIQUE INDEX "devices_mac_address_key" ON "devices"("mac_address");

-- CreateIndex
CREATE UNIQUE INDEX "vulnerabilities_cve_id_key" ON "vulnerabilities"("cve_id");

-- AddForeignKey
ALTER TABLE "scan_jobs" ADD CONSTRAINT "scan_jobs_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("user_id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "scan_results" ADD CONSTRAINT "scan_results_scan_id_fkey" FOREIGN KEY ("scan_id") REFERENCES "scan_jobs"("scan_id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "scan_results" ADD CONSTRAINT "scan_results_device_id_fkey" FOREIGN KEY ("device_id") REFERENCES "devices"("device_id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "scan_results" ADD CONSTRAINT "scan_results_vuln_id_fkey" FOREIGN KEY ("vuln_id") REFERENCES "vulnerabilities"("vuln_id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "risk_assessments" ADD CONSTRAINT "risk_assessments_device_id_fkey" FOREIGN KEY ("device_id") REFERENCES "devices"("device_id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "risk_assessments" ADD CONSTRAINT "risk_assessments_scan_id_fkey" FOREIGN KEY ("scan_id") REFERENCES "scan_jobs"("scan_id") ON DELETE RESTRICT ON UPDATE CASCADE;
