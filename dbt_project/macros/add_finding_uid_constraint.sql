-- Macro to conditionally add finding_uid format constraint based on dbt variables
--
-- PURPOSE:
-- Supports upstream pattern where different organizations can enforce
-- different UID format requirements without modifying upstream code.
--
-- This solves a key challenge with dbt packages: downstream projects cannot extend
-- schema.yml definitions from upstream packages (dbt throws "duplicate entry" error).
--
-- HOW IT WORKS:
-- 1. Post-hook executes after table creation
-- 2. Reads 'finding_uid_format_pattern' variable from dbt_project.yml
-- 3. If pattern is set: Adds CHECK constraint to validate format
-- 4. If pattern is null: Skips constraint (allows any UID format)
--
-- UPSTREAM/DOWNSTREAM STRATEGY:
-- - Upstream (generic OCSF platform): Sets variable to null (no format constraint)
--   Example: finding_uid_format_pattern: null
--
--   Example: finding_uid_format_pattern: '^boann:[^:]+:[^:]+:[^:]+:.+$'
--
-- - Other Organizations: Define their own UID format patterns
--   Example: finding_uid_format_pattern: '^acme:[^:]+:[^:]+:.+$'
--
-- USAGE:
-- 1. In model SQL file:
--   {{ config(
--       post_hook="{{ add_finding_uid_constraint() }}"
--   ) }}
--
-- 2. In dbt_project.yml:
--   vars:
--     # OR: null  # No constraint (generic upstream)
--
-- CHANGING THE PATTERN:
-- The macro automatically detects when the pattern variable changes and updates the
-- constraint accordingly. When you change finding_uid_format_pattern in dbt_project.yml
-- and run dbt, the macro will:
--   1. Check if existing constraint matches the new pattern
--   2. If different: Drop old constraint and create new one
--   3. If same: Skip (no changes needed)
--   4. Validate existing data against new pattern (fails if data doesn't match)
--
-- Example - changing the pattern:
--   1. Update dbt_project.yml: finding_uid_format_pattern: '^acme:[^:]+:.+$'
--   2. Run: dbt run --select raw_ocsf_findings stg_ocsf_findings
--   3. Macro automatically updates the constraint
--
-- IMPORTANT: If existing data doesn't match the new pattern, the constraint add will
-- fail with a CHECK constraint violation error. This is intentional to prevent silent
-- data quality issues. In this case, you have two options:
--   a) Fix the existing data to match the new pattern first
--   b) Use --full-refresh to recreate the table (loses existing data)
--
-- INITIAL APPLICATION:
-- When applying this to existing tables for the first time, use --full-refresh:
--   dbt run --full-refresh --select raw_ocsf_findings stg_ocsf_findings

{% macro add_finding_uid_constraint() %}
    {% set pattern = var('finding_uid_format_pattern', none) %}
    {% set constraint_name = this.identifier ~ '_finding_uid_format_check' %}

    {% if pattern is not none %}
        -- Add constraint if pattern is specified
        {{ log("Adding finding_uid format constraint to " ~ this ~ " with pattern: " ~ pattern, info=false) }}
        DO $$
        DECLARE
            existing_pattern TEXT;
        BEGIN
            -- Check if constraint exists and get its current pattern
            SELECT pg_get_constraintdef(oid) INTO existing_pattern
            FROM pg_constraint
            WHERE conname = '{{ constraint_name }}'
              AND conrelid = '{{ this }}'::regclass;

            -- If constraint exists but pattern is different, drop and recreate
            IF existing_pattern IS NOT NULL AND existing_pattern NOT LIKE '%{{ pattern }}%' THEN
                ALTER TABLE {{ this }} DROP CONSTRAINT {{ constraint_name }};
                existing_pattern := NULL;  -- Force recreation below
            END IF;

            -- Add constraint if it doesn't exist (or was just dropped)
            IF existing_pattern IS NULL THEN
                ALTER TABLE {{ this }}
                ADD CONSTRAINT {{ constraint_name }}
                CHECK (finding_uid ~ '{{ pattern }}');
            END IF;
        END $$;
    {% else %}
        -- No constraint specified, skip (allows generic upstream usage)
        -- Return valid SQL no-op to avoid "empty query" error
        {{ log("No finding_uid_format_pattern specified, skipping format constraint for " ~ this, info=false) }}
        SELECT 1 WHERE FALSE; -- No-op: returns immediately without doing anything
    {% endif %}
{% endmacro %}

