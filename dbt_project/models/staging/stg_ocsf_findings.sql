-- models/staging/stg_ocsf_findings.sql
-- Staging model that extracts and standardizes raw OCSF JSON data.
-- See dbt_project/models/schema.yaml for full documentation.

{{ config(
    materialized='incremental',
    incremental_strategy='append',
    on_schema_change='append_new_columns',
    description='Staging model that extracts and standardizes raw OCSF JSON data from landing.raw_ocsf_findings. Preserves all findings from all scans without deduplication.',
    post_hook=[
        "{{ add_finding_uid_constraint() }}",
        "{{ add_new_indexes([
            {'name': 'idx_stg_ocsf_findings_loaded_at', 'columns': ['staging_loaded_at'], 'type': 'btree'}
        ]) }}"
    ]
) }}

WITH source_data AS (
    SELECT *
    FROM {{ ref('raw_ocsf_findings') }} AS raw
    WHERE 1=1
    {% if is_incremental() %}
        -- Incremental filter: process only records loaded after the latest processed timestamp.
        AND loaded_at > (
            SELECT COALESCE(MAX(staging_loaded_at), '1970-01-01'::timestamptz)
            FROM {{ this }}
        )
    {% endif %}
)

SELECT
    finding_uid,

    -- Tool metadata
    raw_ocsf_json -> 'metadata' -> 'product' ->> 'name' AS tool_name,
    raw_ocsf_json -> 'metadata' -> 'product' ->> 'version' AS tool_version,

    -- Scan run ID from enrichments (custom extension for deterministic scan grouping)
    -- Extracted from scan_metadata enrichment's data field
    (
        SELECT obj.value -> 'data' ->> 'scan_run_id'
        FROM jsonb_array_elements(COALESCE(raw_ocsf_json -> 'enrichments', '[]'::jsonb)) AS obj
        WHERE obj.value ->> 'name' = 'scan_metadata'
        LIMIT 1
    ) AS scan_run_id,

    -- Convert the original_time from milliseconds Unix timestamp to PostgreSQL's default TIMESTAMPTZ.
    -- If original_time is missing or zero, store NULL to avoid default epoch timestamp.
    TO_TIMESTAMP(
        NULLIF((raw_ocsf_json -> 'finding_info' ->> 'created_time')::NUMERIC / 1000.0, 0)
    ) AS detected_at,

    loaded_at AS staging_loaded_at,

    -- Finding core attributes - extracted directly as strings
    raw_ocsf_json -> 'finding_info' ->> 'title' AS finding_title,
    raw_ocsf_json -> 'finding_info' ->> 'desc' AS finding_description,
    raw_ocsf_json -> 'finding_info' ->> 'src_url' AS finding_src_url,
    raw_ocsf_json ->> 'severity' AS finding_severity,
    raw_ocsf_json ->> 'status' AS finding_status,
    raw_ocsf_json ->> 'activity_name' AS finding_activity_name,

    -- Extract remediation guidance if available
    raw_ocsf_json -> 'remediation' ->> 'desc' AS finding_remediation,

    -- Extract complete resources array as JSONB (no filtering)
    COALESCE(raw_ocsf_json -> 'resources', '[]'::jsonb) AS resources_jsonb,

    -- Aggregate all affected_packages from all vulnerabilities into a single JSONB array
    (
        SELECT jsonb_agg(pkg)
        FROM (
            SELECT jsonb_array_elements(COALESCE(vuln.value -> 'affected_packages', '[]'::jsonb)) AS pkg
            FROM jsonb_array_elements(COALESCE(raw_ocsf_json -> 'vulnerabilities', '[]'::jsonb)) AS vuln
            WHERE vuln.value -> 'affected_packages' IS NOT NULL
        ) AS all_pkgs
    ) AS affected_packages_jsonb,

    -- Extract OCSF vulnerabilities array with affected_code and affected_packages relationship preserved
    -- Note: OCSF uses "vulnerabilities" to represent both CVEs and CWEs
    -- A finding can have multiple entries in vulnerabilities array, each with its own file location and affected components
    -- Keeping these together ensures we know which file/line belongs to which component
    -- Example: [{affected_code: {file: "api.py", line: 10}, affected_packages: [{name: "component-a"}]}]
    (
        SELECT jsonb_agg(
            jsonb_build_object(
                'affected_code', vuln.value -> 'affected_code',
                'affected_packages', vuln.value -> 'affected_packages'
            )
        )
        FROM jsonb_array_elements(COALESCE(raw_ocsf_json -> 'vulnerabilities', '[]'::jsonb)) AS vuln
        WHERE vuln.value -> 'affected_packages' IS NOT NULL
           OR vuln.value -> 'affected_code' IS NOT NULL
    ) AS vulnerabilities_subset_jsonb,

    -- Aggregate all CWEs from OCSF vulnerabilities array into a single JSONB array
    -- Includes both direct CWEs and CWEs related to CVEs
    (
        SELECT jsonb_agg(DISTINCT cwe_id)
        FROM (
            -- Direct CWEs from OCSF vulnerabilities entry (object format)
            SELECT vuln.value -> 'cwe' ->> 'uid' AS cwe_id
            FROM jsonb_array_elements(COALESCE(raw_ocsf_json -> 'vulnerabilities', '[]'::jsonb)) AS vuln
            WHERE vuln.value -> 'cwe' ->> 'uid' IS NOT NULL

            UNION ALL

            -- CWEs from related_cwes within CVEs in OCSF vulnerabilities array
            SELECT related_cwe.value ->> 'uid' AS cwe_id
            FROM jsonb_array_elements(COALESCE(raw_ocsf_json -> 'vulnerabilities', '[]'::jsonb)) AS vuln,
                 jsonb_array_elements(COALESCE(vuln.value -> 'cve' -> 'related_cwes', '[]'::jsonb)) AS related_cwe
            WHERE vuln.value -> 'cve' -> 'related_cwes' IS NOT NULL
              AND related_cwe.value ->> 'uid' IS NOT NULL
        ) AS all_cwes
        WHERE cwe_id IS NOT NULL
    ) AS finding_cwes,

    -- Aggregate all CVEs from OCSF vulnerabilities array into a single JSONB array
    (
        SELECT jsonb_agg(DISTINCT cve_id)
        FROM (
            SELECT vuln.value -> 'cve' ->> 'uid' AS cve_id
            FROM jsonb_array_elements(COALESCE(raw_ocsf_json -> 'vulnerabilities', '[]'::jsonb)) AS vuln
            WHERE vuln.value -> 'cve' -> 'uid' IS NOT NULL
        ) AS all_cves
    ) AS finding_cves,

    -- Aggregate all references from OCSF vulnerabilities array into a single JSONB array
    (
        SELECT jsonb_agg(DISTINCT reference_url)
        FROM (
            SELECT jsonb_array_elements_text(COALESCE(vuln.value -> 'references', '[]'::jsonb)) AS reference_url
            FROM jsonb_array_elements(COALESCE(raw_ocsf_json -> 'vulnerabilities', '[]'::jsonb)) AS vuln
            WHERE vuln.value -> 'references' IS NOT NULL
        ) AS all_references
    ) AS finding_references,

    -- Extract enrichment source
    (
        SELECT obj.value ->> 'value'
        FROM jsonb_array_elements(COALESCE(raw_ocsf_json -> 'enrichments', '[]'::jsonb)) AS obj
        WHERE obj.value ->> 'name' = 'rh_sdlc_source'
        LIMIT 1
    ) AS finding_source,

    -- Extract complete affected_components enrichment object as JSONB
    (
        SELECT obj.value
        FROM jsonb_array_elements(COALESCE(raw_ocsf_json -> 'enrichments', '[]'::jsonb)) AS obj
        WHERE obj.value ->> 'name' = 'affected_components'
        LIMIT 1
    ) AS enrichments_affected_components_jsonb,

    -- Extract Jira status (status + resolution) enrichment object as JSONB
    (
        SELECT obj.value
        FROM jsonb_array_elements(COALESCE(raw_ocsf_json -> 'enrichments', '[]'::jsonb)) AS obj
        WHERE obj.value ->> 'name' = 'jira_status'
        LIMIT 1
    ) AS enrichments_jira_status_jsonb


FROM source_data raw
