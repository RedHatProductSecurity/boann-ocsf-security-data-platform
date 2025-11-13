-- Test that finding_severity only contains valid severity levels
-- Valid values: Critical, High, Medium, Low, Informational, Unknown
select
    finding_uid,
    finding_severity
from {{ ref('stg_ocsf_findings') }}
where finding_severity not in ('Critical', 'High', 'Medium', 'Low', 'Informational', 'Unknown')

