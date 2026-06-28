package io.github.hectorvent.floci.services.transfer.model;

import java.time.Instant;
import java.util.Map;

public class Connector {

    private String connectorId;
    private String arn;
    private String url;
    private String accessRole;
    private String loggingRole;
    private SftpConnectorConfig sftpConfig;
    private String securityPolicyName;
    private Map<String, String> tags;
    private Instant creationTime;

    public Connector() {}

    public String getConnectorId() { return connectorId; }
    public void setConnectorId(String connectorId) { this.connectorId = connectorId; }

    public String getArn() { return arn; }
    public void setArn(String arn) { this.arn = arn; }

    public String getUrl() { return url; }
    public void setUrl(String url) { this.url = url; }

    public String getAccessRole() { return accessRole; }
    public void setAccessRole(String accessRole) { this.accessRole = accessRole; }

    public String getLoggingRole() { return loggingRole; }
    public void setLoggingRole(String loggingRole) { this.loggingRole = loggingRole; }

    public SftpConnectorConfig getSftpConfig() { return sftpConfig; }
    public void setSftpConfig(SftpConnectorConfig sftpConfig) { this.sftpConfig = sftpConfig; }

    public String getSecurityPolicyName() { return securityPolicyName; }
    public void setSecurityPolicyName(String securityPolicyName) { this.securityPolicyName = securityPolicyName; }

    public Map<String, String> getTags() { return tags; }
    public void setTags(Map<String, String> tags) { this.tags = tags; }

    public Instant getCreationTime() { return creationTime; }
    public void setCreationTime(Instant creationTime) { this.creationTime = creationTime; }
}
