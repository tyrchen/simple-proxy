use super::{WafChecker, WafMsg};
use crate::conf::{ProxyConfigResolved};
use anyhow::Result;
use papaya::HashMap;
use std::sync::Arc;
// use std::ops::Deref;
use regex::Regex;

impl WafChecker {
    pub fn try_new(config: &ProxyConfigResolved) -> Result<Self> {
        
        let rules = HashMap::new();
        {
            let pinned = rules.pin();
            for (param, vec) in config.waf_rules.rules.iter() {
                let regex_vec: Vec<Regex> = vec.iter().map(|rule| Regex::new(rule).unwrap()).collect();
                pinned.insert(param.clone(), regex_vec.clone());
            }
        }

        let param_types = config.waf_rules.param_types.clone();

        Ok(WafChecker{
            rules: Arc::new(rules),
            param_types: Arc::new(param_types),
        })
    }

    fn common_check(&self, val: &str, rules: &Vec<Regex>) -> bool {
        for rule in rules {
            if rule.is_match(val) {
                return true;
            }
        }
        false
    }

    pub fn rule_check(&self, base_msg: &WafMsg) -> (bool, Option<&str>) {

        let rules = self.rules.pin();

        for param in self.param_types.iter() {
            let matched = match param.as_str() {
                "user_agent" => self.common_check(&base_msg.user_agent, rules.get("user_agent").unwrap_or(&vec![])),
                "url" => self.common_check(&base_msg.url, rules.get("url").unwrap_or(&vec![])),
                "cookie" => self.common_check(&base_msg.cookie, rules.get("cookie").unwrap_or(&vec![])),
                "post" => self.common_check(&base_msg.post, rules.get("post").unwrap_or(&vec![])),
                "args" => self.common_check(&base_msg.args, rules.get("args").unwrap_or(&vec![])),
                _ => false,
            };
    
            if matched {
                return (true, Some(param));
            }
        }
    
        (false, None)
    }
   
}

