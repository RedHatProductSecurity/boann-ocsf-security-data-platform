-- Macro to create indexes using post-hooks instead of dbt's native indexes config
--
-- Why this exists:
-- In PostgreSQL, dbt creates indexes during initial table materialization within
-- the same transaction as the CREATE statement. If you add new indexes to an
-- existing model's configuration after the table was created, dbt won't add them.
--
-- This macro solves that by using post-hooks to create indexes after table creation,
-- ensuring indexes are always applied regardless of when they were added to the config.
--
-- Usage:
-- {{ config(
--     post_hook="{{ add_new_indexes([
--         {'name': 'idx_my_column', 'columns': ['my_column'], 'type': 'btree'},
--         {'name': 'idx_unique_key', 'columns': ['unique_key'], 'unique': true}
--     ]) }}"
-- ) }}

{% macro add_new_indexes(new_indexes) %}
  {%- for index in new_indexes -%}
    CREATE {% if index.unique %}UNIQUE {% endif %}INDEX IF NOT EXISTS {{ index.name }}
    ON {{ this }}
    {%- if index.type and index.type != 'btree' %} USING {{ index.type }}{% endif %}
    ({{ index.columns | join(', ') }});
  {%- endfor -%}
{% endmacro %}

