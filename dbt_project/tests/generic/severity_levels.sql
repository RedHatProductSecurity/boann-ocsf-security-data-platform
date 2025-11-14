{% test severity_levels(model, column_name) %}
    select
        {{ column_name }}
    from {{ model }}
    where {{ column_name }} not in ('Critical', 'High', 'Medium', 'Low', 'Informational', 'Unknown', 'Other')
{% endtest %}

