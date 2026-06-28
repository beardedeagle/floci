package io.github.hectorvent.floci.services.transfer.model;

import java.util.List;

public class SftpConnectorConfig {

    private String userSecretId;
    private List<String> trustedHostKeys;

    public SftpConnectorConfig() {}

    public String getUserSecretId() { return userSecretId; }
    public void setUserSecretId(String userSecretId) { this.userSecretId = userSecretId; }

    public List<String> getTrustedHostKeys() { return trustedHostKeys; }
    public void setTrustedHostKeys(List<String> trustedHostKeys) { this.trustedHostKeys = trustedHostKeys; }
}
