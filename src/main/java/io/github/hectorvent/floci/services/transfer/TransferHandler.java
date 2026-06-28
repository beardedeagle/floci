package io.github.hectorvent.floci.services.transfer;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.JsonErrorResponseUtils;
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
import jakarta.ws.rs.core.Response;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@ApplicationScoped
public class TransferHandler {

    private final TransferService service;
    private final ObjectMapper objectMapper;

    @Inject
    public TransferHandler(TransferService service, ObjectMapper objectMapper) {
        this.service = service;
        this.objectMapper = objectMapper;
    }

    public Response handle(String action, JsonNode request, String region) {
        try {
            return switch (action) {
                case "CreateServer"       -> createServer(request, region);
                case "DescribeServer"     -> describeServer(request);
                case "DeleteServer"       -> deleteServer(request);
                case "ListServers"        -> listServers(request);
                case "StartServer"        -> startServer(request);
                case "StopServer"         -> stopServer(request);
                case "UpdateServer"       -> updateServer(request);
                case "CreateUser"         -> createUser(request, region);
                case "DescribeUser"       -> describeUser(request);
                case "DeleteUser"         -> deleteUser(request);
                case "ListUsers"          -> listUsers(request);
                case "UpdateUser"         -> updateUser(request);
                case "CreateConnector"    -> createConnector(request, region);
                case "DescribeConnector"  -> describeConnector(request);
                case "ListConnectors"     -> listConnectors(request);
                case "DeleteConnector"    -> deleteConnector(request);
                case "TestConnection"          -> testConnection(request, region);
                case "StartDirectoryListing"   -> startDirectoryListing(request, region);
                case "StartFileTransfer"       -> startFileTransfer(request, region);
                case "ListFileTransferResults" -> listFileTransferResults(request);
                case "ImportSshPublicKey" -> importSshPublicKey(request);
                case "DeleteSshPublicKey" -> deleteSshPublicKey(request);
                case "TagResource"        -> tagResource(request);
                case "UntagResource"      -> untagResource(request);
                case "ListTagsForResource" -> listTagsForResource(request);
                default -> JsonErrorResponseUtils.createUnknownOperationErrorResponse("AmazonTransfer." + action);
            };
        } catch (AwsException e) {
            return JsonErrorResponseUtils.createErrorResponse(e);
        } catch (Exception e) {
            return JsonErrorResponseUtils.createErrorResponse(e);
        }
    }

    // ── Server handlers ───────────────────────────────────────────────────────

    private Response createServer(JsonNode req, String region) {
        List<String> protocols = jsonStringList(req.path("Protocols"));
        String endpointType = textOrNull(req, "EndpointType");
        Map<String, Object> endpointDetails = jsonObjectMap(req.path("EndpointDetails"));
        String identityProviderType = textOrNull(req, "IdentityProviderType");
        Map<String, String> identityProviderDetails = jsonStringMap(req.path("IdentityProviderDetails"));
        String loggingRole = textOrNull(req, "LoggingRole");
        String securityPolicyName = textOrNull(req, "SecurityPolicyName");
        Map<String, String> tags = parseTags(req.path("Tags"));

        Server server = service.createServer(region, protocols, endpointType, endpointDetails,
                identityProviderType, identityProviderDetails, loggingRole, securityPolicyName, tags);

        ObjectNode resp = objectMapper.createObjectNode();
        resp.put("ServerId", server.getServerId());
        return Response.ok(resp).build();
    }

    private Response describeServer(JsonNode req) {
        String serverId = req.path("ServerId").asText();
        Server server = service.getServer(serverId);
        ObjectNode resp = objectMapper.createObjectNode();
        resp.set("Server", buildServerNode(server));
        return Response.ok(resp).build();
    }

    private Response deleteServer(JsonNode req) {
        service.deleteServer(req.path("ServerId").asText());
        return Response.ok(objectMapper.createObjectNode()).build();
    }

    private Response listServers(JsonNode req) {
        String nextToken = textOrNull(req, "NextToken");
        int maxResults = req.path("MaxResults").asInt(100);
        List<Server> servers = service.listServers(nextToken, maxResults);

        ObjectNode resp = objectMapper.createObjectNode();
        ArrayNode arr = resp.putArray("Servers");
        for (Server s : servers) {
            arr.add(buildServerListEntry(s));
        }
        if (servers.size() == maxResults) {
            resp.put("NextToken", servers.get(servers.size() - 1).getServerId());
        }
        return Response.ok(resp).build();
    }

    private Response startServer(JsonNode req) {
        service.startServer(req.path("ServerId").asText());
        return Response.ok(objectMapper.createObjectNode()).build();
    }

    private Response stopServer(JsonNode req) {
        service.stopServer(req.path("ServerId").asText());
        return Response.ok(objectMapper.createObjectNode()).build();
    }

    private Response updateServer(JsonNode req) {
        String serverId = req.path("ServerId").asText();
        List<String> protocols = jsonStringList(req.path("Protocols"));
        String endpointType = textOrNull(req, "EndpointType");
        Map<String, Object> endpointDetails = jsonObjectMap(req.path("EndpointDetails"));
        String identityProviderDetails = textOrNull(req, "IdentityProviderDetails");
        String loggingRole = textOrNull(req, "LoggingRole");
        String securityPolicyName = textOrNull(req, "SecurityPolicyName");

        Server server = service.updateServer(serverId, protocols, endpointType, endpointDetails,
                identityProviderDetails, loggingRole, securityPolicyName);

        ObjectNode resp = objectMapper.createObjectNode();
        resp.put("ServerId", server.getServerId());
        return Response.ok(resp).build();
    }

    // ── User handlers ─────────────────────────────────────────────────────────

    private Response createUser(JsonNode req, String region) {
        String serverId = req.path("ServerId").asText();
        String userName = req.path("UserName").asText();
        String role = textOrNull(req, "Role");
        String homeDirectory = textOrNull(req, "HomeDirectory");
        String homeDirectoryType = textOrNull(req, "HomeDirectoryType");
        List<HomeDirectoryMapping> mappings = parseHomeDirectoryMappings(req.path("HomeDirectoryMappings"));
        Map<String, String> tags = parseTags(req.path("Tags"));

        if (userName == null || userName.isEmpty()) {
            throw new AwsException("InvalidRequestException", "UserName is required.", 400);
        }
        if (role == null || role.isEmpty()) {
            throw new AwsException("InvalidRequestException", "Role is required.", 400);
        }

        User user = service.createUser(serverId, region, userName, role, homeDirectory,
                homeDirectoryType, mappings, tags);

        ObjectNode resp = objectMapper.createObjectNode();
        resp.put("ServerId", serverId);
        resp.put("UserName", user.getUserName());
        return Response.ok(resp).build();
    }

    private Response describeUser(JsonNode req) {
        String serverId = req.path("ServerId").asText();
        String userName = req.path("UserName").asText();
        User user = service.getUser(serverId, userName);

        ObjectNode resp = objectMapper.createObjectNode();
        resp.put("ServerId", serverId);
        resp.set("User", buildUserNode(user));
        return Response.ok(resp).build();
    }

    private Response deleteUser(JsonNode req) {
        service.deleteUser(req.path("ServerId").asText(), req.path("UserName").asText());
        return Response.ok(objectMapper.createObjectNode()).build();
    }

    private Response listUsers(JsonNode req) {
        String serverId = req.path("ServerId").asText();
        String nextToken = textOrNull(req, "NextToken");
        int maxResults = req.path("MaxResults").asInt(100);
        List<User> users = service.listUsers(serverId, nextToken, maxResults);

        ObjectNode resp = objectMapper.createObjectNode();
        resp.put("ServerId", serverId);
        ArrayNode arr = resp.putArray("Users");
        for (User u : users) {
            arr.add(buildUserListEntry(u));
        }
        if (users.size() == maxResults) {
            resp.put("NextToken", users.get(users.size() - 1).getUserName());
        }
        return Response.ok(resp).build();
    }

    private Response updateUser(JsonNode req) {
        String serverId = req.path("ServerId").asText();
        String userName = req.path("UserName").asText();
        String role = textOrNull(req, "Role");
        String homeDirectory = textOrNull(req, "HomeDirectory");
        String homeDirectoryType = textOrNull(req, "HomeDirectoryType");
        List<HomeDirectoryMapping> mappings = parseHomeDirectoryMappings(req.path("HomeDirectoryMappings"));

        User user = service.updateUser(serverId, userName, role, homeDirectory, homeDirectoryType,
                mappings.isEmpty() ? null : mappings);

        ObjectNode resp = objectMapper.createObjectNode();
        resp.put("ServerId", serverId);
        resp.put("UserName", user.getUserName());
        return Response.ok(resp).build();
    }

    // ── Connector handlers ────────────────────────────────────────────────────

    private Response createConnector(JsonNode req, String region) {
        String url = textOrNull(req, "Url");
        String accessRole = textOrNull(req, "AccessRole");
        String loggingRole = textOrNull(req, "LoggingRole");
        String securityPolicyName = textOrNull(req, "SecurityPolicyName");
        SftpConnectorConfig sftpConfig = parseSftpConfig(req.path("SftpConfig"));
        Map<String, String> tags = parseTags(req.path("Tags"));

        if (url == null || url.isEmpty()) {
            throw new AwsException("InvalidRequestException", "Url is required.", 400);
        }
        if (accessRole == null || accessRole.isEmpty()) {
            throw new AwsException("InvalidRequestException", "AccessRole is required.", 400);
        }

        Connector connector = service.createConnector(region, url, accessRole, loggingRole,
                sftpConfig, securityPolicyName, tags);

        ObjectNode resp = objectMapper.createObjectNode();
        resp.put("ConnectorId", connector.getConnectorId());
        return Response.ok(resp).build();
    }

    private Response describeConnector(JsonNode req) {
        String connectorId = req.path("ConnectorId").asText();
        Connector connector = service.getConnector(connectorId);
        ObjectNode resp = objectMapper.createObjectNode();
        resp.set("Connector", buildConnectorNode(connector));
        return Response.ok(resp).build();
    }

    private Response listConnectors(JsonNode req) {
        String nextToken = textOrNull(req, "NextToken");
        int maxResults = req.path("MaxResults").asInt(100);
        if (maxResults < 1 || maxResults > 1000) {
            throw new AwsException("InvalidRequestException", "MaxResults must be between 1 and 1000.", 400);
        }
        // Over-fetch by one so we can tell whether more results exist beyond this
        // page: NextToken must only be returned when there genuinely is a next page,
        // otherwise clients paginate into an empty response.
        List<Connector> page = service.listConnectors(nextToken, maxResults + 1);
        boolean hasMore = page.size() > maxResults;
        if (hasMore) {
            page = page.subList(0, maxResults);
        }

        ObjectNode resp = objectMapper.createObjectNode();
        ArrayNode arr = resp.putArray("Connectors");
        for (Connector c : page) {
            arr.add(buildConnectorListEntry(c));
        }
        if (hasMore) {
            resp.put("NextToken", page.get(page.size() - 1).getConnectorId());
        }
        return Response.ok(resp).build();
    }

    private Response deleteConnector(JsonNode req) {
        service.deleteConnector(req.path("ConnectorId").asText());
        return Response.ok(objectMapper.createObjectNode()).build();
    }

    private Response testConnection(JsonNode req, String region) {
        String connectorId = req.path("ConnectorId").asText();
        TransferService.ConnectionTest result = service.testConnection(connectorId, region);
        ObjectNode resp = objectMapper.createObjectNode();
        resp.put("ConnectorId", connectorId);
        resp.put("Status", result.status());
        resp.put("StatusMessage", result.statusMessage());
        if (result.hostKey() != null) {
            ObjectNode details = resp.putObject("SftpConnectionDetails");
            details.put("HostKey", result.hostKey());
        }
        return Response.ok(resp).build();
    }

    private Response startDirectoryListing(JsonNode req, String region) {
        String connectorId = req.path("ConnectorId").asText();
        String remoteDirectoryPath = textOrNull(req, "RemoteDirectoryPath");
        String outputDirectoryPath = textOrNull(req, "OutputDirectoryPath");
        int maxItems = req.path("MaxItems").asInt(0);
        if (remoteDirectoryPath == null) {
            throw new AwsException("InvalidRequestException", "RemoteDirectoryPath is required.", 400);
        }
        if (outputDirectoryPath == null) {
            throw new AwsException("InvalidRequestException", "OutputDirectoryPath is required.", 400);
        }
        TransferService.DirectoryListing listing = service.startDirectoryListing(
                connectorId, region, remoteDirectoryPath, outputDirectoryPath, maxItems);
        ObjectNode resp = objectMapper.createObjectNode();
        resp.put("ListingId", listing.listingId());
        resp.put("OutputFileName", listing.outputFileName());
        return Response.ok(resp).build();
    }

    private Response startFileTransfer(JsonNode req, String region) {
        String connectorId = req.path("ConnectorId").asText();
        List<String> retrieveFilePaths = jsonStringList(req.path("RetrieveFilePaths"));
        String localDirectoryPath = textOrNull(req, "LocalDirectoryPath");
        if (retrieveFilePaths.isEmpty()) {
            throw new AwsException("InvalidRequestException", "RetrieveFilePaths is required.", 400);
        }
        if (localDirectoryPath == null) {
            throw new AwsException("InvalidRequestException", "LocalDirectoryPath is required.", 400);
        }
        String transferId = service.startFileTransfer(connectorId, region, retrieveFilePaths, localDirectoryPath);
        ObjectNode resp = objectMapper.createObjectNode();
        resp.put("TransferId", transferId);
        return Response.ok(resp).build();
    }

    private Response listFileTransferResults(JsonNode req) {
        String connectorId = req.path("ConnectorId").asText();
        String transferId = req.path("TransferId").asText();
        TransferRecord record = service.listFileTransferResults(connectorId, transferId);
        ObjectNode resp = objectMapper.createObjectNode();
        ArrayNode arr = resp.putArray("FileTransferResults");
        for (FileTransferResult r : record.getResults()) {
            ObjectNode n = arr.addObject();
            n.put("FilePath", r.getFilePath());
            n.put("StatusCode", r.getStatusCode());
            if (r.getFailureCode() != null) {
                n.put("FailureCode", r.getFailureCode());
            }
            if (r.getFailureMessage() != null) {
                n.put("FailureMessage", r.getFailureMessage());
            }
        }
        return Response.ok(resp).build();
    }

    // ── SSH key handlers ──────────────────────────────────────────────────────

    private Response importSshPublicKey(JsonNode req) {
        String serverId = req.path("ServerId").asText();
        String userName = req.path("UserName").asText();
        String body = req.path("SshPublicKeyBody").asText();

        SshPublicKey key = service.importSshPublicKey(serverId, userName, body);

        ObjectNode resp = objectMapper.createObjectNode();
        resp.put("ServerId", serverId);
        resp.put("SshPublicKeyId", key.getSshPublicKeyId());
        resp.put("UserName", userName);
        return Response.ok(resp).build();
    }

    private Response deleteSshPublicKey(JsonNode req) {
        service.deleteSshPublicKey(
                req.path("ServerId").asText(),
                req.path("UserName").asText(),
                req.path("SshPublicKeyId").asText());
        return Response.ok(objectMapper.createObjectNode()).build();
    }

    // ── Tag handlers ──────────────────────────────────────────────────────────

    private Response tagResource(JsonNode req) {
        String arn = req.path("Arn").asText();
        Map<String, String> tags = parseTags(req.path("Tags"));
        service.tagResource(arn, tags);
        return Response.ok(objectMapper.createObjectNode()).build();
    }

    private Response untagResource(JsonNode req) {
        String arn = req.path("Arn").asText();
        List<String> keys = new ArrayList<>();
        req.path("TagKeys").forEach(n -> keys.add(n.asText()));
        service.untagResource(arn, keys);
        return Response.ok(objectMapper.createObjectNode()).build();
    }

    private Response listTagsForResource(JsonNode req) {
        String arn = req.path("Arn").asText();
        Map<String, String> tags = service.listTagsForResource(arn);
        ObjectNode resp = objectMapper.createObjectNode();
        resp.put("Arn", arn);
        ArrayNode arr = resp.putArray("Tags");
        tags.forEach((k, v) -> {
            ObjectNode tag = objectMapper.createObjectNode();
            tag.put("Key", k);
            tag.put("Value", v);
            arr.add(tag);
        });
        return Response.ok(resp).build();
    }

    // ── JSON builders ─────────────────────────────────────────────────────────

    private ObjectNode buildServerNode(Server s) {
        ObjectNode node = objectMapper.createObjectNode();
        node.put("ServerId", s.getServerId());
        node.put("Arn", s.getArn());
        node.put("State", s.getState());
        node.put("EndpointType", s.getEndpointType());
        node.put("IdentityProviderType", s.getIdentityProviderType());
        node.put("SecurityPolicyName", s.getSecurityPolicyName());
        node.put("HostKeyFingerprint", s.getHostKeyFingerprint());
        node.put("UserCount", service.countUsers(s.getServerId()));
        if (s.getLoggingRole() != null) {
            node.put("LoggingRole", s.getLoggingRole());
        }
        if (s.getProtocols() != null) {
            ArrayNode protocols = node.putArray("Protocols");
            s.getProtocols().forEach(protocols::add);
        }
        if (s.getTags() != null && !s.getTags().isEmpty()) {
            ArrayNode tags = node.putArray("Tags");
            s.getTags().forEach((k, v) -> {
                ObjectNode tag = objectMapper.createObjectNode();
                tag.put("Key", k);
                tag.put("Value", v);
                tags.add(tag);
            });
        }
        return node;
    }

    private ObjectNode buildServerListEntry(Server s) {
        ObjectNode node = objectMapper.createObjectNode();
        node.put("Arn", s.getArn());
        node.put("EndpointType", s.getEndpointType());
        node.put("IdentityProviderType", s.getIdentityProviderType());
        node.put("ServerId", s.getServerId());
        node.put("State", s.getState());
        node.put("UserCount", service.countUsers(s.getServerId()));
        if (s.getLoggingRole() != null) {
            node.put("LoggingRole", s.getLoggingRole());
        }
        return node;
    }

    private ObjectNode buildUserNode(User u) {
        ObjectNode node = objectMapper.createObjectNode();
        node.put("UserName", u.getUserName());
        node.put("Arn", u.getArn());
        node.put("HomeDirectory", u.getHomeDirectory());
        node.put("HomeDirectoryType", u.getHomeDirectoryType());
        if (u.getRole() != null) node.put("Role", u.getRole());
        if (u.getHomeDirectoryMappings() != null && !u.getHomeDirectoryMappings().isEmpty()) {
            ArrayNode arr = node.putArray("HomeDirectoryMappings");
            for (HomeDirectoryMapping m : u.getHomeDirectoryMappings()) {
                ObjectNode entry = objectMapper.createObjectNode();
                entry.put("Entry", m.getEntry());
                entry.put("Target", m.getTarget());
                arr.add(entry);
            }
        }
        ArrayNode keys = node.putArray("SshPublicKeys");
        if (u.getSshPublicKeys() != null) {
            for (SshPublicKey k : u.getSshPublicKeys()) {
                ObjectNode kNode = objectMapper.createObjectNode();
                kNode.put("SshPublicKeyId", k.getSshPublicKeyId());
                kNode.put("SshPublicKeyBody", k.getSshPublicKeyBody());
                if (k.getDateImported() != null) {
                    kNode.put("DateImported", k.getDateImported().toString());
                }
                keys.add(kNode);
            }
        }
        if (u.getTags() != null && !u.getTags().isEmpty()) {
            ArrayNode tags = node.putArray("Tags");
            u.getTags().forEach((k, v) -> {
                ObjectNode tag = objectMapper.createObjectNode();
                tag.put("Key", k);
                tag.put("Value", v);
                tags.add(tag);
            });
        }
        return node;
    }

    private ObjectNode buildUserListEntry(User u) {
        ObjectNode node = objectMapper.createObjectNode();
        node.put("UserName", u.getUserName());
        node.put("Arn", u.getArn());
        node.put("HomeDirectory", u.getHomeDirectory());
        node.put("HomeDirectoryType", u.getHomeDirectoryType());
        if (u.getRole() != null) node.put("Role", u.getRole());
        node.put("SshPublicKeyCount", u.getSshPublicKeys() != null ? u.getSshPublicKeys().size() : 0);
        return node;
    }

    private ObjectNode buildConnectorNode(Connector c) {
        ObjectNode node = objectMapper.createObjectNode();
        node.put("Arn", c.getArn());
        node.put("ConnectorId", c.getConnectorId());
        node.put("Url", c.getUrl());
        if (c.getAccessRole() != null) node.put("AccessRole", c.getAccessRole());
        if (c.getLoggingRole() != null) node.put("LoggingRole", c.getLoggingRole());
        if (c.getSecurityPolicyName() != null) node.put("SecurityPolicyName", c.getSecurityPolicyName());
        if (c.getSftpConfig() != null) {
            ObjectNode sftp = node.putObject("SftpConfig");
            if (c.getSftpConfig().getUserSecretId() != null) {
                sftp.put("UserSecretId", c.getSftpConfig().getUserSecretId());
            }
            ArrayNode keys = sftp.putArray("TrustedHostKeys");
            if (c.getSftpConfig().getTrustedHostKeys() != null) {
                c.getSftpConfig().getTrustedHostKeys().forEach(keys::add);
            }
        }
        if (c.getTags() != null && !c.getTags().isEmpty()) {
            ArrayNode tags = node.putArray("Tags");
            c.getTags().forEach((k, v) -> {
                ObjectNode tag = objectMapper.createObjectNode();
                tag.put("Key", k);
                tag.put("Value", v);
                tags.add(tag);
            });
        }
        return node;
    }

    private ObjectNode buildConnectorListEntry(Connector c) {
        ObjectNode node = objectMapper.createObjectNode();
        node.put("Arn", c.getArn());
        node.put("ConnectorId", c.getConnectorId());
        node.put("Url", c.getUrl());
        return node;
    }

    // ── Parsing helpers ───────────────────────────────────────────────────────

    private String textOrNull(JsonNode node, String field) {
        JsonNode child = node.path(field);
        return child.isMissingNode() || child.isNull() ? null : child.asText();
    }

    private List<String> jsonStringList(JsonNode node) {
        List<String> list = new ArrayList<>();
        if (node != null && node.isArray()) {
            node.forEach(n -> list.add(n.asText()));
        }
        return list;
    }

    private Map<String, String> jsonStringMap(JsonNode node) {
        Map<String, String> map = new HashMap<>();
        if (node != null && node.isObject()) {
            node.fields().forEachRemaining(e -> map.put(e.getKey(), e.getValue().asText()));
        }
        return map;
    }

    private Map<String, Object> jsonObjectMap(JsonNode node) {
        if (node == null || node.isMissingNode() || node.isNull()) {
            return null;
        }
        Map<String, Object> map = new HashMap<>();
        node.fields().forEachRemaining(e -> map.put(e.getKey(), e.getValue().asText()));
        return map.isEmpty() ? null : map;
    }

    private Map<String, String> parseTags(JsonNode node) {
        Map<String, String> tags = new HashMap<>();
        if (node != null && node.isArray()) {
            node.forEach(t -> {
                String key = t.path("Key").asText(null);
                String value = t.path("Value").asText("");
                if (key != null) tags.put(key, value);
            });
        }
        return tags;
    }

    private List<HomeDirectoryMapping> parseHomeDirectoryMappings(JsonNode node) {
        List<HomeDirectoryMapping> list = new ArrayList<>();
        if (node != null && node.isArray()) {
            node.forEach(m -> {
                String entry = m.path("Entry").asText(null);
                String target = m.path("Target").asText(null);
                if (entry != null && target != null) {
                    list.add(new HomeDirectoryMapping(entry, target));
                }
            });
        }
        return list;
    }

    private SftpConnectorConfig parseSftpConfig(JsonNode node) {
        if (node == null || node.isMissingNode() || node.isNull()) {
            return null;
        }
        SftpConnectorConfig cfg = new SftpConnectorConfig();
        cfg.setUserSecretId(textOrNull(node, "UserSecretId"));
        cfg.setTrustedHostKeys(jsonStringList(node.path("TrustedHostKeys")));
        return cfg;
    }
}
