package io.github.hectorvent.floci.services.transfer;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.core.storage.StorageBackend;
import io.github.hectorvent.floci.core.storage.StorageFactory;
import io.github.hectorvent.floci.services.s3.S3Service;
import io.github.hectorvent.floci.services.secretsmanager.SecretsManagerService;
import io.github.hectorvent.floci.services.secretsmanager.model.SecretVersion;
import io.github.hectorvent.floci.services.transfer.model.Connector;
import io.github.hectorvent.floci.services.transfer.model.FileTransferResult;
import io.github.hectorvent.floci.services.transfer.model.HomeDirectoryMapping;
import io.github.hectorvent.floci.services.transfer.model.Server;
import io.github.hectorvent.floci.services.transfer.model.SftpConnectorConfig;
import io.github.hectorvent.floci.services.transfer.model.SshPublicKey;
import io.github.hectorvent.floci.services.transfer.model.TransferRecord;
import io.github.hectorvent.floci.services.transfer.model.User;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.net.URI;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@ApplicationScoped
public class TransferService {

    private static final Logger LOG = Logger.getLogger(TransferService.class);

    private static final String CHARS = "abcdefghijklmnopqrstuvwxyz0123456789";

    private final StorageBackend<String, Server> serverStore;
    private final StorageBackend<String, User> userStore;
    private final StorageBackend<String, Connector> connectorStore;
    private final StorageBackend<String, TransferRecord> transferResultStore;
    private final StorageBackend<String, Map<String, String>> tagStore;
    private final RegionResolver regionResolver;
    private final S3Service s3Service;
    private final SecretsManagerService secretsManagerService;
    private final SftpConnectorClient sftpClient;
    private final ObjectMapper objectMapper;

    @Inject
    public TransferService(StorageFactory factory, EmulatorConfig config, RegionResolver regionResolver,
                           S3Service s3Service, SecretsManagerService secretsManagerService,
                           SftpConnectorClient sftpClient, ObjectMapper objectMapper) {
        this.serverStore = factory.create("transfer", "transfer-servers.json",
                new TypeReference<Map<String, Server>>() {});
        this.userStore = factory.create("transfer", "transfer-users.json",
                new TypeReference<Map<String, User>>() {});
        this.connectorStore = factory.create("transfer", "transfer-connectors.json",
                new TypeReference<Map<String, Connector>>() {});
        this.transferResultStore = factory.create("transfer", "transfer-file-transfer-results.json",
                new TypeReference<Map<String, TransferRecord>>() {});
        this.tagStore = factory.create("transfer", "transfer-tags.json",
                new TypeReference<Map<String, Map<String, String>>>() {});
        this.regionResolver = regionResolver;
        this.s3Service = s3Service;
        this.secretsManagerService = secretsManagerService;
        this.sftpClient = sftpClient;
        this.objectMapper = objectMapper;
    }

    // ── Servers ───────────────────────────────────────────────────────────────

    public Server createServer(String region,
                               List<String> protocols,
                               String endpointType,
                               Map<String, Object> endpointDetails,
                               String identityProviderType,
                               Map<String, String> identityProviderDetails,
                               String loggingRole,
                               String securityPolicyName,
                               Map<String, String> tags) {
        String serverId = generateServerId();
        String arn = "arn:aws:transfer:" + region + ":" + regionResolver.getAccountId() + ":server/" + serverId;

        Server server = new Server();
        server.setServerId(serverId);
        server.setArn(arn);
        server.setState("ONLINE");
        server.setProtocols(protocols != null && !protocols.isEmpty() ? protocols : List.of("SFTP"));
        server.setEndpointType(endpointType != null ? endpointType : "PUBLIC");
        server.setEndpointDetails(endpointDetails);
        server.setIdentityProviderType(identityProviderType != null ? identityProviderType : "SERVICE_MANAGED");
        server.setIdentityProviderDetails(identityProviderDetails);
        server.setLoggingRole(loggingRole);
        server.setSecurityPolicyName(securityPolicyName != null ? securityPolicyName : "TransferSecurityPolicy-2020-06");
        server.setHostKeyFingerprint("SHA256:AAAAflociemulatedkey" + serverId.substring(2, 10));
        server.setTags(tags != null ? tags : new HashMap<>());
        server.setCreationTime(Instant.now());

        serverStore.put(serverId, server);

        if (tags != null && !tags.isEmpty()) {
            tagStore.put("server/" + serverId, new HashMap<>(tags));
        }

        return server;
    }

    public Server getServer(String serverId) {
        return serverStore.get(serverId).orElseThrow(() ->
                new AwsException("ResourceNotFoundException",
                        "Server " + serverId + " does not exist.", 404));
    }

    public synchronized void deleteServer(String serverId) {
        Server server = getServer(serverId);
        if (!"OFFLINE".equals(server.getState())) {
            throw new AwsException("ConflictException",
                    "Server must be in OFFLINE state to be deleted.", 409);
        }
        serverStore.delete(serverId);
        tagStore.delete("server/" + serverId);
        for (User user : userStore.scan(k -> k.startsWith(serverId + "/"))) {
            userStore.delete(serverId + "/" + user.getUserName());
            tagStore.delete("user/" + serverId + "/" + user.getUserName());
        }
    }

    public List<Server> listServers(String nextToken, int maxResults) {
        List<Server> all = new ArrayList<>(serverStore.scan(k -> true));
        all.sort((a, b) -> a.getServerId().compareTo(b.getServerId()));
        if (nextToken != null && !nextToken.isEmpty()) {
            int idx = 0;
            for (int i = 0; i < all.size(); i++) {
                if (all.get(i).getServerId().equals(nextToken)) {
                    idx = i + 1;
                    break;
                }
            }
            all = all.subList(idx, all.size());
        }
        if (maxResults > 0 && all.size() > maxResults) {
            return all.subList(0, maxResults);
        }
        return all;
    }

    public Server startServer(String serverId) {
        Server server = getServer(serverId);
        if (!"OFFLINE".equals(server.getState())) {
            throw new AwsException("ConflictException",
                    "Server is not in OFFLINE state.", 409);
        }
        server.setState("ONLINE");
        serverStore.put(serverId, server);
        return server;
    }

    public Server stopServer(String serverId) {
        Server server = getServer(serverId);
        if (!"ONLINE".equals(server.getState())) {
            throw new AwsException("ConflictException",
                    "Server is not in ONLINE state.", 409);
        }
        server.setState("OFFLINE");
        serverStore.put(serverId, server);
        return server;
    }

    public Server updateServer(String serverId,
                               List<String> protocols,
                               String endpointType,
                               Map<String, Object> endpointDetails,
                               String identityProviderDetails,
                               String loggingRole,
                               String securityPolicyName) {
        Server server = getServer(serverId);
        if (protocols != null && !protocols.isEmpty()) {
            server.setProtocols(protocols);
        }
        if (endpointType != null) {
            server.setEndpointType(endpointType);
        }
        if (endpointDetails != null) {
            server.setEndpointDetails(endpointDetails);
        }
        if (loggingRole != null) {
            server.setLoggingRole(loggingRole);
        }
        if (securityPolicyName != null) {
            server.setSecurityPolicyName(securityPolicyName);
        }
        serverStore.put(serverId, server);
        return server;
    }

    // ── Users ─────────────────────────────────────────────────────────────────

    public User createUser(String serverId, String region, String userName, String role,
                           String homeDirectory, String homeDirectoryType,
                           List<HomeDirectoryMapping> homeDirectoryMappings,
                           Map<String, String> tags) {
        getServer(serverId);
        String key = serverId + "/" + userName;
        if (userStore.get(key).isPresent()) {
            throw new AwsException("ResourceExistsException",
                    "User " + userName + " already exists on server " + serverId + ".", 400);
        }

        String arn = "arn:aws:transfer:" + region + ":" + regionResolver.getAccountId() + ":user/" + serverId + "/" + userName;
        User user = new User();
        user.setUserName(userName);
        user.setArn(arn);
        user.setRole(role);
        user.setHomeDirectory(homeDirectory != null ? homeDirectory : "/");
        user.setHomeDirectoryType(homeDirectoryType != null ? homeDirectoryType : "PATH");
        user.setHomeDirectoryMappings(homeDirectoryMappings != null ? homeDirectoryMappings : List.of());
        user.setSshPublicKeys(new ArrayList<>());
        user.setTags(tags != null ? tags : new HashMap<>());

        userStore.put(key, user);

        if (tags != null && !tags.isEmpty()) {
            tagStore.put("user/" + key, new HashMap<>(tags));
        }

        return user;
    }

    public User getUser(String serverId, String userName) {
        getServer(serverId);
        return userStore.get(serverId + "/" + userName).orElseThrow(() ->
                new AwsException("ResourceNotFoundException",
                        "User " + userName + " does not exist on server " + serverId + ".", 404));
    }

    public void deleteUser(String serverId, String userName) {
        getUser(serverId, userName);
        String key = serverId + "/" + userName;
        userStore.delete(key);
        tagStore.delete("user/" + key);
    }

    public List<User> listUsers(String serverId, String nextToken, int maxResults) {
        getServer(serverId);
        List<User> all = new ArrayList<>(userStore.scan(k -> k.startsWith(serverId + "/")));
        all.sort((a, b) -> a.getUserName().compareTo(b.getUserName()));
        if (nextToken != null && !nextToken.isEmpty()) {
            int idx = 0;
            for (int i = 0; i < all.size(); i++) {
                if (all.get(i).getUserName().equals(nextToken)) {
                    idx = i + 1;
                    break;
                }
            }
            all = all.subList(idx, all.size());
        }
        if (maxResults > 0 && all.size() > maxResults) {
            return all.subList(0, maxResults);
        }
        return all;
    }

    public User updateUser(String serverId, String userName, String role,
                           String homeDirectory, String homeDirectoryType,
                           List<HomeDirectoryMapping> homeDirectoryMappings) {
        User user = getUser(serverId, userName);
        if (role != null) user.setRole(role);
        if (homeDirectory != null) user.setHomeDirectory(homeDirectory);
        if (homeDirectoryType != null) user.setHomeDirectoryType(homeDirectoryType);
        if (homeDirectoryMappings != null) user.setHomeDirectoryMappings(homeDirectoryMappings);
        userStore.put(serverId + "/" + userName, user);
        return user;
    }

    // ── Connectors ────────────────────────────────────────────────────────────

    public Connector createConnector(String region, String url, String accessRole,
                                     String loggingRole, SftpConnectorConfig sftpConfig,
                                     String securityPolicyName, Map<String, String> tags) {
        parseUrl(url); // reject a non-sftp:// or hostless URL at create time (matches AWS)
        String connectorId = generateConnectorId();
        String arn = "arn:aws:transfer:" + region + ":" + regionResolver.getAccountId() + ":connector/" + connectorId;

        Connector connector = new Connector();
        connector.setConnectorId(connectorId);
        connector.setArn(arn);
        connector.setUrl(url);
        connector.setAccessRole(accessRole);
        connector.setLoggingRole(loggingRole);
        connector.setSftpConfig(sftpConfig);
        connector.setSecurityPolicyName(securityPolicyName != null ? securityPolicyName : "TransferSecurityPolicy-2020-06");
        connector.setTags(tags != null ? tags : new HashMap<>());
        connector.setCreationTime(Instant.now());

        connectorStore.put(connectorId, connector);

        if (tags != null && !tags.isEmpty()) {
            tagStore.put("connector/" + connectorId, new HashMap<>(tags));
        }

        return connector;
    }

    public Connector getConnector(String connectorId) {
        return connectorStore.get(connectorId).orElseThrow(() ->
                new AwsException("ResourceNotFoundException",
                        "Connector " + connectorId + " does not exist.", 404));
    }

    public List<Connector> listConnectors(String nextToken, int maxResults) {
        List<Connector> all = new ArrayList<>(connectorStore.scan(k -> true));
        all.sort((a, b) -> a.getConnectorId().compareTo(b.getConnectorId()));
        if (nextToken != null && !nextToken.isEmpty()) {
            int idx = -1;
            for (int i = 0; i < all.size(); i++) {
                if (all.get(i).getConnectorId().equals(nextToken)) {
                    idx = i + 1;
                    break;
                }
            }
            if (idx < 0) {
                throw new AwsException("InvalidRequestException",
                        "The provided NextToken is not valid.", 400);
            }
            all = all.subList(idx, all.size());
        }
        if (maxResults > 0 && all.size() > maxResults) {
            return all.subList(0, maxResults);
        }
        return all;
    }

    public void deleteConnector(String connectorId) {
        getConnector(connectorId);
        connectorStore.delete(connectorId);
        tagStore.delete("connector/" + connectorId);
    }

    // ── Connector data plane (SFTP <-> S3) ────────────────────────────────────

    public ConnectionTest testConnection(String connectorId, String region) {
        Connector connector = getConnector(connectorId);
        URI uri = parseUrl(connector.getUrl());
        try {
            SftpConnectorClient.SftpCredentials creds = resolveCredentials(connector, region);
            String hostKey = sftpClient.fetchHostKey(uri.getHost(), port(uri), creds, trustedHostKeys(connector));
            return new ConnectionTest("OK", "Connection succeeded", hostKey);
        } catch (Exception e) {
            LOG.warn("TestConnection failed for connector " + connectorId, e);
            return new ConnectionTest("ERROR", "Connection failed.", null);
        }
    }

    public DirectoryListing startDirectoryListing(String connectorId, String region,
                                                  String remoteDirectoryPath, String outputDirectoryPath,
                                                  int maxItems) {
        Connector connector = getConnector(connectorId);
        SftpConnectorClient.SftpCredentials creds = resolveCredentials(connector, region);
        URI uri = parseUrl(connector.getUrl());

        List<SftpConnectorClient.RemoteEntry> entries;
        try {
            entries = sftpClient.listDirectory(uri.getHost(), port(uri), creds,
                    trustedHostKeys(connector), remoteDirectoryPath);
        } catch (Exception e) {
            LOG.warn("Directory listing failed for connector " + connectorId, e);
            throw new AwsException("InternalServiceError", "Directory listing failed.", 500);
        }

        ObjectNode root = objectMapper.createObjectNode();
        ArrayNode files = root.putArray("files");
        ArrayNode paths = root.putArray("paths");
        boolean truncated = false;
        int count = 0;
        for (SftpConnectorClient.RemoteEntry e : entries) {
            if (maxItems > 0 && count >= maxItems) {
                truncated = true;
                break;
            }
            if (e.directory()) {
                paths.add(joinPath(remoteDirectoryPath, e.name()));
            } else {
                ObjectNode f = files.addObject();
                f.put("filePath", joinPath(remoteDirectoryPath, e.name()));
                f.put("modifiedTimestamp", Instant.ofEpochMilli(e.modifiedEpochMillis()).toString());
                f.put("size", e.size());
            }
            count++;
        }
        root.put("truncated", truncated);

        String listingId = UUID.randomUUID().toString();
        String outputFileName = connectorId + "-" + listingId + ".json";
        String[] bk = parseS3Path(outputDirectoryPath);
        String key = bk[1].isEmpty() ? outputFileName : bk[1] + "/" + outputFileName;
        byte[] body;
        try {
            body = objectMapper.writeValueAsBytes(root);
        } catch (Exception e) {
            LOG.warn("Failed to serialize directory listing for connector " + connectorId, e);
            throw new AwsException("InternalServiceError", "Failed to serialize directory listing.", 500);
        }
        s3Service.createBucket(bk[0], region);
        s3Service.putObject(bk[0], key, body, "application/json", new HashMap<>());
        return new DirectoryListing(listingId, outputFileName);
    }

    public String startFileTransfer(String connectorId, String region,
                                    List<String> retrieveFilePaths, String localDirectoryPath) {
        Connector connector = getConnector(connectorId);
        SftpConnectorClient.SftpCredentials creds = resolveCredentials(connector, region);
        URI uri = parseUrl(connector.getUrl());
        String[] bk = parseS3Path(localDirectoryPath);
        s3Service.createBucket(bk[0], region);

        List<FileTransferResult> results = new ArrayList<>();
        try {
            List<SftpConnectorClient.FileFetch> fetched = sftpClient.retrieveFiles(
                    uri.getHost(), port(uri), creds, trustedHostKeys(connector), retrieveFilePaths);
            for (SftpConnectorClient.FileFetch f : fetched) {
                FileTransferResult result = new FileTransferResult();
                result.setFilePath(f.remotePath());
                if (f.errorMessage() != null) {
                    LOG.warn("File retrieve failed for connector " + connectorId + " path "
                            + f.remotePath() + ": " + f.errorMessage());
                    result.setStatusCode("FAILED");
                    result.setFailureCode("RETRIEVE_FAILED");
                    result.setFailureMessage("Failed to retrieve the file from the SFTP server.");
                } else {
                    try {
                        String key = (bk[1].isEmpty() ? "" : bk[1] + "/") + basename(f.remotePath());
                        s3Service.putObject(bk[0], key, f.data(), "application/octet-stream", new HashMap<>());
                        result.setStatusCode("COMPLETED");
                    } catch (Exception e) {
                        LOG.warn("S3 write failed for connector " + connectorId + " path " + f.remotePath(), e);
                        result.setStatusCode("FAILED");
                        result.setFailureCode("WRITE_FAILED");
                        result.setFailureMessage("Failed to write the file to the local S3 destination.");
                    }
                }
                results.add(result);
            }
        } catch (Exception e) {
            // Session-level failure (connect/auth/host-key): mark every requested file failed.
            LOG.warn("StartFileTransfer session failed for connector " + connectorId, e);
            for (String remotePath : retrieveFilePaths) {
                FileTransferResult result = new FileTransferResult();
                result.setFilePath(remotePath);
                result.setStatusCode("FAILED");
                result.setFailureCode("CONNECTION_FAILED");
                result.setFailureMessage("Failed to connect to the SFTP server.");
                results.add(result);
            }
        }

        String transferId = UUID.randomUUID().toString();
        TransferRecord record = new TransferRecord();
        record.setTransferId(transferId);
        record.setConnectorId(connectorId);
        record.setResults(results);
        transferResultStore.put(transferId, record);
        return transferId;
    }

    public TransferRecord listFileTransferResults(String connectorId, String transferId) {
        TransferRecord record = transferResultStore.get(transferId).orElseThrow(() ->
                new AwsException("ResourceNotFoundException",
                        "Transfer " + transferId + " does not exist.", 404));
        // Scope the lookup to the supplied connector: a transfer created under a
        // different connector must not be retrievable here (per-connector isolation).
        if (!record.getConnectorId().equals(connectorId)) {
            throw new AwsException("ResourceNotFoundException",
                    "Transfer " + transferId + " does not exist for connector " + connectorId + ".", 404);
        }
        return record;
    }

    private List<String> trustedHostKeys(Connector connector) {
        SftpConnectorConfig cfg = connector.getSftpConfig();
        return cfg == null ? null : cfg.getTrustedHostKeys();
    }

    private SftpConnectorClient.SftpCredentials resolveCredentials(Connector connector, String region) {
        SftpConnectorConfig cfg = connector.getSftpConfig();
        if (cfg == null || cfg.getUserSecretId() == null || cfg.getUserSecretId().isEmpty()) {
            throw new AwsException("InvalidRequestException",
                    "Connector " + connector.getConnectorId() + " has no SftpConfig.UserSecretId.", 400);
        }
        SecretVersion version = secretsManagerService.getSecretValue(cfg.getUserSecretId(), null, null, region);
        if (version.getSecretString() == null || version.getSecretString().isBlank()) {
            throw new AwsException("InvalidRequestException",
                    "Connector secret " + cfg.getUserSecretId() + " has no SecretString.", 400);
        }
        String username;
        String password;
        String privateKey;
        try {
            JsonNode node = objectMapper.readTree(version.getSecretString());
            username = node.path("Username").asText(null);
            password = node.path("Password").asText(null);
            privateKey = node.path("PrivateKey").asText(null);
        } catch (Exception e) {
            throw new AwsException("InvalidRequestException",
                    "Connector secret is not valid JSON: " + e.getMessage(), 400);
        }
        if (username == null || username.isBlank()) {
            throw new AwsException("InvalidRequestException",
                    "Connector secret must contain a Username.", 400);
        }
        if ((password == null || password.isBlank()) && (privateKey == null || privateKey.isBlank())) {
            throw new AwsException("InvalidRequestException",
                    "Connector secret must contain a Password or PrivateKey.", 400);
        }
        return new SftpConnectorClient.SftpCredentials(username, password, privateKey);
    }

    private URI parseUrl(String url) {
        if (url == null || url.isEmpty()) {
            throw new AwsException("InvalidRequestException", "Connector URL is missing.", 400);
        }
        URI uri;
        try {
            uri = URI.create(url);
        } catch (Exception e) {
            throw new AwsException("InvalidRequestException", "Invalid connector URL: " + url, 400);
        }
        if (!"sftp".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null || uri.getHost().isBlank()) {
            throw new AwsException("InvalidRequestException",
                    "Connector URL must be an sftp://<host>[:port] URL, got: " + url, 400);
        }
        return uri;
    }

    private int port(URI uri) {
        return uri.getPort() > 0 ? uri.getPort() : 22;
    }

    private String[] parseS3Path(String path) {
        if (path == null || path.isBlank()) {
            throw new AwsException("InvalidRequestException", "S3 directory path is required.", 400);
        }
        String p = path.startsWith("/") ? path.substring(1) : path;
        int slash = p.indexOf('/');
        String bucket = slash < 0 ? p : p.substring(0, slash);
        if (bucket.isEmpty()) {
            throw new AwsException("InvalidRequestException",
                    "S3 directory path must include a bucket: " + path, 400);
        }
        // Strip trailing slashes from the key prefix so callers that append "/" don't
        // produce double-slash keys ("prefix//file").
        String prefix = (slash < 0 ? "" : p.substring(slash + 1)).replaceAll("/+$", "");
        return new String[]{bucket, prefix};
    }

    private String basename(String path) {
        int idx = path.lastIndexOf('/');
        return idx >= 0 ? path.substring(idx + 1) : path;
    }

    private String joinPath(String dir, String name) {
        if (dir == null || dir.isEmpty()) {
            return name;
        }
        return dir.endsWith("/") ? dir + name : dir + "/" + name;
    }

    public record ConnectionTest(String status, String statusMessage, String hostKey) {}

    public record DirectoryListing(String listingId, String outputFileName) {}

    // ── SSH Keys ──────────────────────────────────────────────────────────────

    public SshPublicKey importSshPublicKey(String serverId, String userName, String sshPublicKeyBody) {
        User user = getUser(serverId, userName);
        String keyId = "key-" + UUID.randomUUID().toString().replace("-", "").substring(0, 17);
        SshPublicKey key = new SshPublicKey(keyId, sshPublicKeyBody, Instant.now());
        List<SshPublicKey> keys = new ArrayList<>(user.getSshPublicKeys() != null ? user.getSshPublicKeys() : List.of());
        keys.add(key);
        user.setSshPublicKeys(keys);
        userStore.put(serverId + "/" + userName, user);
        return key;
    }

    public void deleteSshPublicKey(String serverId, String userName, String sshPublicKeyId) {
        User user = getUser(serverId, userName);
        List<SshPublicKey> keys = new ArrayList<>(user.getSshPublicKeys() != null ? user.getSshPublicKeys() : List.of());
        boolean removed = keys.removeIf(k -> k.getSshPublicKeyId().equals(sshPublicKeyId));
        if (!removed) {
            throw new AwsException("ResourceNotFoundException",
                    "SSH public key " + sshPublicKeyId + " does not exist.", 404);
        }
        user.setSshPublicKeys(keys);
        userStore.put(serverId + "/" + userName, user);
    }

    // ── Tags ──────────────────────────────────────────────────────────────────

    public Map<String, String> listTagsForResource(String arn) {
        String key = arnToTagKey(arn);
        return tagStore.get(key).orElse(new HashMap<>());
    }

    public void tagResource(String arn, Map<String, String> tags) {
        String key = arnToTagKey(arn);
        Map<String, String> existing = new HashMap<>(tagStore.get(key).orElse(new HashMap<>()));
        existing.putAll(tags);
        tagStore.put(key, existing);

        // Also sync tags into the resource object
        syncTagsToResource(arn, existing);
    }

    public void untagResource(String arn, List<String> tagKeys) {
        String key = arnToTagKey(arn);
        Map<String, String> existing = new HashMap<>(tagStore.get(key).orElse(new HashMap<>()));
        tagKeys.forEach(existing::remove);
        tagStore.put(key, existing);
        syncTagsToResource(arn, existing);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private String generateServerId() {
        StringBuilder sb = new StringBuilder("s-");
        String uuid = UUID.randomUUID().toString().replace("-", "");
        sb.append(uuid, 0, 17);
        return sb.toString();
    }

    private String generateConnectorId() {
        StringBuilder sb = new StringBuilder("c-");
        String uuid = UUID.randomUUID().toString().replace("-", "");
        sb.append(uuid, 0, 17);
        return sb.toString();
    }

    private String arnToTagKey(String arn) {
        // arn:aws:transfer:region:account:server/s-xxx  → server/s-xxx
        // arn:aws:transfer:region:account:user/s-xxx/alice → user/s-xxx/alice
        int idx = arn.lastIndexOf(':');
        return idx >= 0 ? arn.substring(idx + 1) : arn;
    }

    private void syncTagsToResource(String arn, Map<String, String> tags) {
        String key = arnToTagKey(arn);
        if (key.startsWith("server/")) {
            String serverId = key.substring("server/".length());
            serverStore.get(serverId).ifPresent(s -> {
                s.setTags(tags);
                serverStore.put(serverId, s);
            });
        } else if (key.startsWith("user/")) {
            String userKey = key.substring("user/".length());
            userStore.get(userKey).ifPresent(u -> {
                u.setTags(tags);
                userStore.put(userKey, u);
            });
        } else if (key.startsWith("connector/")) {
            String connectorId = key.substring("connector/".length());
            connectorStore.get(connectorId).ifPresent(c -> {
                c.setTags(tags);
                connectorStore.put(connectorId, c);
            });
        }
    }

    public int countUsers(String serverId) {
        return (int) userStore.scan(k -> k.startsWith(serverId + "/")).stream().count();
    }
}
