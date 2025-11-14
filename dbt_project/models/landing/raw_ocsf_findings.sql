-- models/landing/raw_ocsf_findings.sql
-- Landing table for raw OCSF JSON data

{{
    config(
        materialized='incremental',
        incremental_strategy='append',
        on_schema_change='append_new_columns',
        description='Initial landing zone for raw OCSF JSON data. Preserves all scan data without deduplication to support instance-level tracking in core layer.',
        post_hook=[
            "{{ add_finding_uid_constraint() }}",
            "{{ add_new_indexes([
                {'name': 'idx_raw_ocsf_findings_finding_uid', 'columns': ['finding_uid'], 'type': 'btree'},
                {'name': 'idx_raw_ocsf_findings_loaded_at', 'columns': ['loaded_at'], 'type': 'btree'}
            ]) }}"
        ]
    )
}}

-- This is a schema-only model. The actual data insertion happens via
-- scripts/ingest_raw_ocsf_findings.py which performs INSERT operations.
-- dbt manages the table structure, Python scripts manage the data.
--
-- IMPORTANT: No unique_key constraint - preserves all findings from all scans.
-- Same finding_uid in different contexts = separate rows.
--
-- Prevents data loss when same finding_uid (same fingerprint) appears in:
-- 1. Different scan times (enables scan-level tracking)
--    Example: SQL injection in curl-7.61.1 scanned on Oct 16 and Oct 20 = 2 rows
-- 2. Different products (enables multi-product tracking)
--    Example: SQL injection in curl-7.61.1 in Fedora 41 and Fedora 42 = 2 rows (same UID)
--
-- Data Lifecycle: Append-only strategy requires periodic cleanup of old raw data
-- to manage storage growth. Implement retention policy based on loaded_at timestamp.

SELECT
    NULL::TEXT AS finding_uid,
    NULL::JSONB AS raw_ocsf_json,
    NULL::TIMESTAMPTZ AS loaded_at
WHERE FALSE  -- Never return rows; table remains unchanged after initial creation

