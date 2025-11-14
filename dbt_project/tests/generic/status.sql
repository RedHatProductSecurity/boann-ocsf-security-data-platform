{% test status_name(model, column_name) %}
    select
        {{ column_name }}
    from {{ model }}
    where {{ column_name }} not in ('Unknown', 'New', 'InProgress', 'Suppressed', 'Resolved', 'Archived', 'Other')
{% endtest %}

