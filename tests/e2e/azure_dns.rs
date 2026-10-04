use crate::common::Lab;

/// The relay's `azure` dns-01 provider, end to end: the upstream (a local
/// CA) issues a `dns-01` challenge, the relay mints a federated token at the
/// mock issuer, exchanges it at the mock Entra, publishes the TXT record
/// through the mock's management plane — which mirrors it into the lab's
/// BIND — and the upstream validates it against BIND and issues the leaf.
#[tokio::test]
#[ignore]
async fn test_relay_signer_azure_dns_01() {
    let lab = Lab::new_with_upstream(
        vec![
            ("ACME_PROXY_SIGNER__BACKEND", "relay"),
            ("ACME_PROXY_SIGNER__RELAY__DIRECTORY_URL", "UPSTREAM_URL"),
            (
                "ACME_PROXY_SIGNER__RELAY__ACCOUNT_KEY_PATH",
                "/tmp/upstream_account.key",
            ),
            ("ACME_PROXY_SIGNER__RELAY__CHALLENGE_STRATEGY", "dns01"),
            ("ACME_PROXY_SIGNER__RELAY__DNS01__PROVIDER", "azure"),
            ("ACME_PROXY_SIGNER__RELAY__DNS01__AZURE__ZONE", "lab."),
            (
                "ACME_PROXY_SIGNER__RELAY__DNS01__AZURE__SUBSCRIPTION_ID",
                "e2e-subscription",
            ),
            (
                "ACME_PROXY_SIGNER__RELAY__DNS01__AZURE__RESOURCE_GROUP",
                "e2e-resource-group",
            ),
            (
                "ACME_PROXY_SIGNER__RELAY__DNS01__AZURE__API_VERSION",
                "2023-07-01-preview",
            ),
            (
                "ACME_PROXY_SIGNER__RELAY__DNS01__AZURE__ISSUER",
                "http://AZURE_MOCK_IP:8080/realms/snohome",
            ),
            (
                "ACME_PROXY_SIGNER__RELAY__DNS01__AZURE__CLIENT_ID",
                "e2e-client",
            ),
            (
                "ACME_PROXY_SIGNER__RELAY__DNS01__AZURE__CLIENT_SECRET",
                "e2e-secret",
            ),
            (
                "ACME_PROXY_SIGNER__RELAY__DNS01__AZURE__ENTRA_TENANT_ID",
                "e2e-tenant",
            ),
            (
                "ACME_PROXY_SIGNER__RELAY__DNS01__AZURE__ENTRA_CLIENT_ID",
                "e2e-entra-app",
            ),
            (
                "ACME_PROXY_SIGNER__RELAY__DNS01__AZURE__ENTRA_AUTHORITY",
                "http://AZURE_MOCK_IP:8080",
            ),
            (
                "ACME_PROXY_SIGNER__RELAY__DNS01__AZURE__ARM_BASE",
                "http://AZURE_MOCK_IP:8080/arm",
            ),
            ("ACME_PROXY_SIGNER__RELAY__POLL_INTERVAL_MS", "500"),
            ("ACME_PROXY_SIGNER__RELAY__POLL_TIMEOUT_SECS", "60"),
        ],
        vec![
            ("ACME_PROXY_CHALLENGE__ENABLED", "dns-01"),
            ("ACME_PROXY_CHALLENGE__BYPASS", "false"),
            ("ACME_PROXY_DNS__RESOLVER", "DNS_SERVER_HOST:53"),
        ],
    )
    .await;

    println!("PROXY LOGS:\n{}", lab.get_proxy_logs().await);

    let certbot_script = format!(
        r#"
        set -e
        mkdir -p /tmp/webroot
        certbot register \
            --agree-tos --email test@example.com \
            --server {0} \
            --config-dir /tmp/certbot/config --work-dir /tmp/certbot/work --logs-dir /tmp/certbot/logs \
            --non-interactive
        certbot certonly \
            --domains signer-azure.lab \
            --server {0} \
            --config-dir /tmp/certbot/config --work-dir /tmp/certbot/work --logs-dir /tmp/certbot/logs \
            --non-interactive \
            --webroot --webroot-path /tmp/webroot
    "#,
        lab.proxy_url
    );

    let (success, out, err) = lab.exec_in_with_output(&lab.certbot, &certbot_script).await;
    if !success {
        println!("Certbot Stdout:\n{}", out);
        println!("Certbot Stderr:\n{}", err);
        println!("PROXY LOGS ON FAILURE:\n{}", lab.get_proxy_logs().await);
        println!(
            "UPSTREAM LOGS ON FAILURE:\n{}",
            lab.get_proxy_upstream_logs().await
        );
        panic!("Certbot failed");
    }

    let proxy_logs = lab.get_proxy_logs().await;
    assert!(
        proxy_logs.contains("upstream_order_opened"),
        "the downstream never opened an upstream order"
    );
    assert!(
        proxy_logs.contains("upstream_relay_succeeded"),
        "the relay never completed"
    );

    let upstream_logs = lab.get_proxy_upstream_logs().await;
    assert!(
        upstream_logs.contains("challenge_dns_01_matched"),
        "the upstream never logged a successful dns-01 match"
    );
}
