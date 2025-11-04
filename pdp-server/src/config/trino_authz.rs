use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Configuration for Trino authorization row filters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrinoAuthzConfig {
    #[serde(rename = "rowFilters")]
    pub row_filters: HashMap<String, Vec<RowFilterConfig>>,
}

/// Configuration for a single row filter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RowFilterConfig {
    pub action: String,
    pub expression: String,
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
            Ok(config) => {
                log::info!(
                    "Successfully loaded Trino authz config from {} with {} resource(s)",
                    path.display(),
                    config.row_filters.len()
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
}
