use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

/// Configuration for Trino authorization row filters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrinoAuthzConfig {
    #[serde(rename = "rowFilters", default)]
    pub row_filters: HashMap<String, Vec<RowFilterConfig>>,
    #[serde(rename = "columnMasking", default)]
    pub column_masks: HashMap<String, ColumnMaskConfig>,
}

/// Configuration for a single row filter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RowFilterConfig {
    pub action: String,
    pub expression: String,
}

/// Configuration for column masking on a table
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColumnMaskConfig {
    /// Optional table-level action (defaults to "AddColumnMask")
    #[serde(default = "default_column_mask_action")]
    pub action: String,
    /// List of columns to mask
    pub columns: Vec<ColumnConfig>,
}

/// Configuration for a single column mask
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColumnConfig {
    /// The name of the column to mask
    pub column_name: String,
    /// The SQL expression to apply as a mask
    pub view_expression: String,
    /// Optional identity to evaluate the expression as
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
    /// Optional action override for this specific column
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
}

fn default_column_mask_action() -> String {
    "AddColumnMask".to_string()
}

impl TrinoAuthzConfig {
    /// Load Trino authorization configuration from a YAML file
    /// Returns None if the file doesn't exist, logs and returns None if parsing fails
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Option<Self> {
        let path = path.as_ref();

        // Check if file exists
        if !path.exists() {
            return None;
        }

        // Read file contents
        let contents = match fs::read_to_string(path) {
            Ok(contents) => contents,
            Err(e) => {
                log::error!(
                    "Failed to read Trino authz config file at {}: {}",
                    path.display(),
                    e
                );
                return None;
            }
        };

        // Parse YAML
        match serde_yaml::from_str::<TrinoAuthzConfig>(&contents) {
            Ok(mut config) => {
                // Validate and deduplicate column masks
                config.validate_and_deduplicate_columns();

                log::info!(
                    "Successfully loaded Trino authz config from {} with {} row filter resource(s) and {} column mask resource(s)",
                    path.display(),
                    config.row_filters.len(),
                    config.column_masks.len()
                );
                Some(config)
            }
            Err(e) => {
                log::error!(
                    "Failed to parse Trino authz config file at {}: {}",
                    path.display(),
                    e
                );
                None
            }
        }
    }

    /// Get row filters for a specific resource
    pub fn get_filters(&self, resource_name: &str) -> Option<&Vec<RowFilterConfig>> {
        self.row_filters.get(resource_name)
    }

    /// Get column masks for a specific resource
    pub fn get_column_masks(&self, resource_name: &str) -> Option<&ColumnMaskConfig> {
        self.column_masks.get(resource_name)
    }

    /// Validate and deduplicate columns in column mask configurations
    /// Keeps the first occurrence of duplicate columns and logs warnings
    fn validate_and_deduplicate_columns(&mut self) {
        for (table_name, mask_config) in self.column_masks.iter_mut() {
            let mut seen_columns = HashSet::new();
            let mut deduplicated_columns = Vec::new();

            for column in &mask_config.columns {
                if seen_columns.contains(&column.column_name) {
                    log::warn!(
                        "Duplicate column '{}' found in column mask config for table '{}'. \
                        Ignoring duplicate, keeping first occurrence.",
                        column.column_name,
                        table_name
                    );
                } else {
                    seen_columns.insert(column.column_name.clone());
                    deduplicated_columns.push(column.clone());
                }
            }

            mask_config.columns = deduplicated_columns;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_load_valid_config() {
        let yaml_content = r#"
rowFilters:
  trino_table_postgres_public_projects:
    - action: only_public
      expression: "is_public = TRUE"
    - action: small_projects
      expression: "size = 'small'"
  trino_table_postgres_public_users:
    - action: view_active
      expression: "status = 'active'"
"#;

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(yaml_content.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let config = TrinoAuthzConfig::load_from_file(temp_file.path());
        assert!(config.is_some());

        let config = config.unwrap();
        assert_eq!(config.row_filters.len(), 2);

        let project_filters = config.get_filters("trino_table_postgres_public_projects");
        assert!(project_filters.is_some());

        let filters = project_filters.unwrap();
        assert_eq!(filters.len(), 2);
        assert_eq!(filters[0].action, "only_public");
        assert_eq!(filters[0].expression, "is_public = TRUE");
        assert_eq!(filters[1].action, "small_projects");
        assert_eq!(filters[1].expression, "size = 'small'");
    }

    #[test]
    fn test_load_nonexistent_file() {
        let config = TrinoAuthzConfig::load_from_file("/nonexistent/path/to/file.yaml");
        assert!(config.is_none());
    }

    #[test]
    fn test_load_invalid_yaml() {
        let invalid_yaml = "invalid: yaml: content: [[[";
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(invalid_yaml.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let config = TrinoAuthzConfig::load_from_file(temp_file.path());
        assert!(config.is_none());
    }

    #[test]
    fn test_get_filters_existing_resource() {
        let yaml_content = r#"
rowFilters:
  test_resource:
    - action: test_action
      expression: "test = TRUE"
"#;

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(yaml_content.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let config = TrinoAuthzConfig::load_from_file(temp_file.path()).unwrap();
        let filters = config.get_filters("test_resource");
        assert!(filters.is_some());
        assert_eq!(filters.unwrap().len(), 1);
    }

    #[test]
    fn test_get_filters_nonexistent_resource() {
        let yaml_content = r#"
rowFilters:
  test_resource:
    - action: test_action
      expression: "test = TRUE"
"#;

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(yaml_content.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let config = TrinoAuthzConfig::load_from_file(temp_file.path()).unwrap();
        let filters = config.get_filters("nonexistent_resource");
        assert!(filters.is_none());
    }

    #[test]
    fn test_load_config_with_column_masking() {
        let yaml_content = r#"
rowFilters:
  trino_table_postgres_public_users:
    - action: view_active
      expression: "status = 'active'"
columnMasking:
  trino_table_postgres_public_users:
    action: AddColumnMask
    columns:
      - column_name: ssn
        view_expression: "'***-**-****'"
      - column_name: email
        view_expression: "CONCAT(SUBSTRING(email, 1, 2), '***@***.com')"
        identity: admin
      - column_name: phone
        view_expression: "'XXX-XXX-XXXX'"
        action: ViewPhone
"#;

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(yaml_content.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let config = TrinoAuthzConfig::load_from_file(temp_file.path());
        assert!(config.is_some());

        let config = config.unwrap();
        assert_eq!(config.column_masks.len(), 1);

        let masks = config.get_column_masks("trino_table_postgres_public_users");
        assert!(masks.is_some());

        let mask_config = masks.unwrap();
        assert_eq!(mask_config.action, "AddColumnMask");
        assert_eq!(mask_config.columns.len(), 3);

        assert_eq!(mask_config.columns[0].column_name, "ssn");
        assert_eq!(mask_config.columns[0].view_expression, "'***-**-****'");
        assert!(mask_config.columns[0].identity.is_none());
        assert!(mask_config.columns[0].action.is_none());

        assert_eq!(mask_config.columns[1].column_name, "email");
        assert_eq!(
            mask_config.columns[1].view_expression,
            "CONCAT(SUBSTRING(email, 1, 2), '***@***.com')"
        );
        assert_eq!(mask_config.columns[1].identity, Some("admin".to_string()));
        assert!(mask_config.columns[1].action.is_none());

        assert_eq!(mask_config.columns[2].column_name, "phone");
        assert_eq!(mask_config.columns[2].view_expression, "'XXX-XXX-XXXX'");
        assert!(mask_config.columns[2].identity.is_none());
        assert_eq!(mask_config.columns[2].action, Some("ViewPhone".to_string()));
    }

    #[test]
    fn test_get_column_masks_nonexistent_resource() {
        let yaml_content = r#"
columnMasking:
  trino_table_test:
    columns:
      - column_name: test_column
        view_expression: "NULL"
"#;

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(yaml_content.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let config = TrinoAuthzConfig::load_from_file(temp_file.path()).unwrap();
        let masks = config.get_column_masks("nonexistent_resource");
        assert!(masks.is_none());
    }

    #[test]
    fn test_default_column_mask_action() {
        let yaml_content = r#"
columnMasking:
  trino_table_test:
    columns:
      - column_name: test_column
        view_expression: "NULL"
"#;

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(yaml_content.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let config = TrinoAuthzConfig::load_from_file(temp_file.path()).unwrap();
        let masks = config.get_column_masks("trino_table_test").unwrap();
        assert_eq!(masks.action, "AddColumnMask");
    }

    #[test]
    fn test_duplicate_column_names_deduplicated() {
        let yaml_content = r#"
columnMasking:
  trino_table_test:
    action: AddColumnMask
    columns:
      - column_name: email
        view_expression: "'FIRST@EXPRESSION.com'"
      - column_name: phone
        view_expression: "'XXX-XXX-XXXX'"
      - column_name: email
        view_expression: "'SECOND@EXPRESSION.com'"
      - column_name: ssn
        view_expression: "'***-**-****'"
      - column_name: email
        view_expression: "'THIRD@EXPRESSION.com'"
"#;

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(yaml_content.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let config = TrinoAuthzConfig::load_from_file(temp_file.path()).unwrap();
        let masks = config.get_column_masks("trino_table_test").unwrap();

        // Should only have 3 unique columns (email, phone, ssn)
        assert_eq!(masks.columns.len(), 3);

        // Verify the first occurrence is kept
        assert_eq!(masks.columns[0].column_name, "email");
        assert_eq!(masks.columns[0].view_expression, "'FIRST@EXPRESSION.com'");

        assert_eq!(masks.columns[1].column_name, "phone");
        assert_eq!(masks.columns[1].view_expression, "'XXX-XXX-XXXX'");

        assert_eq!(masks.columns[2].column_name, "ssn");
        assert_eq!(masks.columns[2].view_expression, "'***-**-****'");
    }

    #[test]
    fn test_duplicate_column_names_multiple_tables() {
        let yaml_content = r#"
columnMasking:
  trino_table_test1:
    columns:
      - column_name: col1
        view_expression: "'FIRST'"
      - column_name: col1
        view_expression: "'SECOND'"
  trino_table_test2:
    columns:
      - column_name: col2
        view_expression: "'FIRST'"
      - column_name: col2
        view_expression: "'SECOND'"
      - column_name: col2
        view_expression: "'THIRD'"
"#;

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(yaml_content.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let config = TrinoAuthzConfig::load_from_file(temp_file.path()).unwrap();

        // Check first table
        let masks1 = config.get_column_masks("trino_table_test1").unwrap();
        assert_eq!(masks1.columns.len(), 1);
        assert_eq!(masks1.columns[0].column_name, "col1");
        assert_eq!(masks1.columns[0].view_expression, "'FIRST'");

        // Check second table
        let masks2 = config.get_column_masks("trino_table_test2").unwrap();
        assert_eq!(masks2.columns.len(), 1);
        assert_eq!(masks2.columns[0].column_name, "col2");
        assert_eq!(masks2.columns[0].view_expression, "'FIRST'");
    }
}
