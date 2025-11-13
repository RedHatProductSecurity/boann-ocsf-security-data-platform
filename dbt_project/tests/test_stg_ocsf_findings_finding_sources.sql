-- Test that finding_source only contains valid source types
-- Valid values: SAST, SCA, DAST, Manual Testing, Jira, Other
select
    finding_uid,
    finding_source
from {{ ref('stg_ocsf_findings') }}
where finding_source not in ('SAST', 'SCA', 'DAST', 'Manual Testing', 'Jira', 'Other')

