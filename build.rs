fn main() {
    let has_v3 = std::env::var("CARGO_FEATURE_V3").is_ok();
    let has_v3_openssl = std::env::var("CARGO_FEATURE_V3_OPENSSL").is_ok();
    let has_v3_rust = std::env::var("CARGO_FEATURE_V3_RUST").is_ok();

    match (has_v3_openssl, has_v3_rust) {
        (true, false) | (false, true) => {} // OK
        (true, true) => panic!("feature_v3_openssl and feature_v3_rust are mutually exclusive!"),
        (false, false) => {
            if has_v3 {
                panic!("feature_v3_openssl or feature_v3_rust is required")
            }
        }
    }
}
