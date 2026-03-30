use std::path::Path;
use std::sync::atomic::{AtomicU8, Ordering};

/// Monotonically increasing counter for assigning each Docker E2E test
/// a unique `/24` subnet, avoiding network collisions under parallel
/// execution.  Starts at 1 to skip `10.0.0.0/24`.
static SUBNET_COUNTER: AtomicU8 = AtomicU8::new(1);

/// Returns a unique subnet like `"10.1.0.0/24"`, `"10.2.0.0/24"`, etc.
pub(crate) fn unique_subnet() -> String {
    let n = SUBNET_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("10.{n}.0.0/24")
}

/// Replaces every segment subnet in the scenario with a unique one so
/// that parallel Docker E2E tests do not collide.
pub(crate) fn isolate_subnets(scenario: &mut crate::scenario::Scenario) {
    for seg in &mut scenario.infrastructure.network.segments {
        seg.subnet = unique_subnet();
    }
}

/// Loads the `ac-0.scenario.yaml` acceptance scenario.
pub(crate) fn load_ac0() -> crate::scenario::Scenario {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("scenarios")
        .join("ac-0.scenario.yaml");
    crate::scenario::load(&path).unwrap()
}

/// Loads the `ac-1-mixed-distro.scenario.yaml` acceptance scenario.
pub(crate) fn load_mixed_distro() -> crate::scenario::Scenario {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("scenarios")
        .join("ac-1-mixed-distro.scenario.yaml");
    crate::scenario::load(&path).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unique_subnet_returns_valid_cidr() {
        let subnet = unique_subnet();
        assert!(
            subnet.parse::<ipnet::Ipv4Net>().is_ok(),
            "not a valid CIDR: {subnet}",
        );
    }

    #[test]
    fn unique_subnet_returns_distinct_values() {
        let a = unique_subnet();
        let b = unique_subnet();
        assert_ne!(a, b);
    }

    #[test]
    fn isolate_subnets_replaces_all_segments() {
        let mut scenario = load_ac0();
        let original = scenario.infrastructure.network.segments[0].subnet.clone();

        isolate_subnets(&mut scenario);

        let replaced = &scenario.infrastructure.network.segments[0].subnet;
        assert_ne!(replaced, &original);
        assert!(
            replaced.parse::<ipnet::Ipv4Net>().is_ok(),
            "replaced subnet is not valid CIDR: {replaced}",
        );
    }

    #[test]
    fn isolate_subnets_gives_distinct_per_call() {
        let mut s1 = load_ac0();
        let mut s2 = load_ac0();
        isolate_subnets(&mut s1);
        isolate_subnets(&mut s2);

        assert_ne!(
            s1.infrastructure.network.segments[0].subnet,
            s2.infrastructure.network.segments[0].subnet,
        );
    }

    #[test]
    fn isolate_subnets_assigns_distinct_per_segment() {
        let yaml = "\
version: '1'
metadata:
  name: multi-seg
  description: test
environment:
  scale: minimal
  encryption: none
  workload: light
  threat: single
  attacker: scripted
duration: 1m
infrastructure:
  hosts:
    - name: h1
      os: linux
      role: attacker
      image: alpine:3.19
    - name: h2
      os: linux
      role: target
      image: alpine:3.19
  network:
    segments:
      - name: dmz
        subnet: 10.0.0.0/24
        hosts:
          - h1
      - name: internal
        subnet: 10.1.0.0/24
        hosts:
          - h2
activities:
  normal: []
  attack: []
";
        let mut scenario: crate::scenario::Scenario = serde_yaml::from_str(yaml).unwrap();
        isolate_subnets(&mut scenario);

        let subnets: Vec<&str> = scenario
            .infrastructure
            .network
            .segments
            .iter()
            .map(|s| s.subnet.as_str())
            .collect();
        assert_ne!(
            subnets[0], subnets[1],
            "each segment must get a distinct subnet"
        );
        for subnet in &subnets {
            assert!(
                subnet.parse::<ipnet::Ipv4Net>().is_ok(),
                "not a valid CIDR: {subnet}",
            );
        }
    }
}
