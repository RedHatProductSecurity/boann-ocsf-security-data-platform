-- Test that finding_status only contains valid OCSF status names
-- Valid values: New, In Progress, Suppressed, Resolved, Other
select
    finding_uid,
    finding_status
from {{ ref('stg_ocsf_findings') }}
where finding_status not in ('New', 'In Progress', 'Suppressed', 'Resolved', 'Other')

