use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TemplateKey {
    pub exporter_ip: IpAddr,
    pub observation_domain_id: u32,
    pub template_id: u16,
}

#[derive(Debug, Clone)]
pub struct TemplateField {
    pub field_type: u16,
    pub field_length: u16,
    pub enterprise_id: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct Template {
    pub key: TemplateKey,
    pub fields: Vec<TemplateField>,
    pub total_length: u16,
}

pub struct TemplateCache {
    templates: HashMap<TemplateKey, Template>,
}

impl Default for TemplateCache {
    fn default() -> Self {
        Self::new()
    }
}

impl TemplateCache {
    pub fn new() -> Self {
        Self {
            templates: HashMap::new(),
        }
    }

    pub fn insert(&mut self, template: Template) {
        self.templates.insert(template.key.clone(), template);
    }

    pub fn get(&self, key: &TemplateKey) -> Option<&Template> {
        self.templates.get(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_key(ip: &str, domain: u32, tid: u16) -> TemplateKey {
        TemplateKey {
            exporter_ip: ip.parse().unwrap(),
            observation_domain_id: domain,
            template_id: tid,
        }
    }

    fn make_template(key: TemplateKey, field_lengths: &[u16]) -> Template {
        let fields: Vec<TemplateField> = field_lengths
            .iter()
            .enumerate()
            .map(|(i, &len)| TemplateField {
                field_type: i as u16 + 1,
                field_length: len,
                enterprise_id: None,
            })
            .collect();
        let total_length = fields.iter().map(|f| f.field_length).sum();
        Template {
            key,
            fields,
            total_length,
        }
    }

    #[test]
    fn test_insert_and_retrieve() {
        let mut cache = TemplateCache::new();
        let key = make_key("10.0.0.1", 0, 256);
        let tmpl = make_template(key.clone(), &[4, 4, 2, 2, 1, 4, 4]);

        cache.insert(tmpl.clone());

        let retrieved = cache.get(&key).expect("template not found");
        assert_eq!(retrieved.key, key);
        assert_eq!(retrieved.fields.len(), 7);
        assert_eq!(retrieved.total_length, 21);
    }

    #[test]
    fn test_replace_existing_key() {
        let mut cache = TemplateCache::new();
        let key = make_key("10.0.0.1", 0, 256);

        let tmpl_v1 = make_template(key.clone(), &[4, 4]);
        cache.insert(tmpl_v1);
        assert_eq!(cache.get(&key).unwrap().total_length, 8);

        let tmpl_v2 = make_template(key.clone(), &[4, 4, 2, 2]);
        cache.insert(tmpl_v2);
        assert_eq!(cache.get(&key).unwrap().total_length, 12);
        assert_eq!(cache.get(&key).unwrap().fields.len(), 4);
    }
}
