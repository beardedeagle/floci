package io.github.hectorvent.floci.services.transfer;

import jakarta.enterprise.context.ApplicationScoped;
import org.jboss.logging.Logger;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.ClientBuilder;
import org.apache.sshd.client.keyverifier.AcceptAllServerKeyVerifier;
import org.apache.sshd.client.keyverifier.ServerKeyVerifier;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.sftp.client.SftpClient;
import org.apache.sshd.sftp.client.SftpClientFactory;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Minimal SFTP client for the AWS Transfer connector data plane: connect to a
 * partner SFTP endpoint (credentials resolved from a Secrets Manager secret), read
 * the server host key, list a remote directory, and retrieve files. Pairs with the
 * connector ops in {@link TransferHandler} / {@link TransferService}.
 *
 * <p>Host-key verification honors the connector's {@code SftpConfig.TrustedHostKeys}:
 * when that list is non-empty the presented server key must match a trusted entry
 * (key-type + base64 blob), otherwise the connection is rejected. When the list is
 * empty/omitted -- the usual local case, where the bundled SFTP container has an
 * ephemeral host key -- verification falls back to permissive (AcceptAll).
 */
@ApplicationScoped
public class SftpConnectorClient {

    private static final Logger LOG = Logger.getLogger(SftpConnectorClient.class);

    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(15);
    private static final Duration AUTH_TIMEOUT = Duration.ofSeconds(15);

    static {
        // Suppress ALL of MINA's security-provider registrars so every algorithm
        // resolves through the JDK's default providers via plain getInstance(algo):
        // X25519/X448 key agreement -> SunEC, rsa host keys -> SunRsaSign, ciphers/
        // MACs -> SunJCE. None of these is a third-party provider, so there is no JCE
        // jar-signature check -- that check is what breaks BouncyCastle-by-name in a
        // native image ("JCE cannot authenticate the provider BC"), and whether a
        // build-time-verified BC instance survives into the image is distribution-
        // dependent (it failed on Oracle GraalVM, worked on CE). The JDK providers
        // ship in every OpenJDK-derived JDK (CE, Mandrel, Temurin), so this path is
        // distribution-agnostic -- important because CI builds the native image with
        // Mandrel. "none" also stops MINA from reflectively loading its default
        // registrar classes (e.g. SunJCESecurityProviderRegistrar), which the native
        // image does not include -> avoids a ClassNotFoundException at first use.
        // floci's own BouncyCastle usage (KMS/ACM) is unaffected: this is MINA-only.
        // ed25519 host keys would need BC or net.i2p (not shipped); the server's rsa
        // host key is negotiated instead. Set once at class load -- before any MINA
        // class is touched, since all MINA use flows through this class.
        System.setProperty("org.apache.sshd.security.registrars", "none");
    }

    public record SftpCredentials(String username, String password, String privateKey) {}

    public record RemoteEntry(String name, long size, long modifiedEpochMillis, boolean directory) {}

    /** Outcome of fetching one remote file in a batch: data on success, errorMessage on failure. */
    public record FileFetch(String remotePath, byte[] data, String errorMessage) {}

    /** Connect and return the server host key in OpenSSH format (e.g. "ssh-rsa AAAA..."). */
    public String fetchHostKey(String host, int port, SftpCredentials creds, List<String> trustedHostKeys)
            throws Exception {
        return withSession(host, port, creds, trustedHostKeys, session ->
                PublicKeyEntry.toString(session.getServerKey()));
    }

    /** List a remote directory (excludes "." and ".."). */
    public List<RemoteEntry> listDirectory(String host, int port, SftpCredentials creds,
                                           List<String> trustedHostKeys, String remotePath)
            throws Exception {
        return withSftp(host, port, creds, trustedHostKeys, sftp -> {
            List<RemoteEntry> entries = new ArrayList<>();
            for (SftpClient.DirEntry e : sftp.readDir(remotePath)) {
                String name = e.getFilename();
                if (".".equals(name) || "..".equals(name)) {
                    continue;
                }
                SftpClient.Attributes attrs = e.getAttributes();
                long size = attrs.getSize();
                long mtime = attrs.getModifyTime() != null ? attrs.getModifyTime().toMillis() : 0L;
                entries.add(new RemoteEntry(name, size, mtime, attrs.isDirectory()));
            }
            return entries;
        });
    }

    /**
     * Retrieve several remote files over a SINGLE SSH session. Per-file failures are
     * captured in the returned {@link FileFetch} (errorMessage non-null) rather than
     * aborting the batch; a session-level failure (connect/auth/host-key) throws.
     */
    public List<FileFetch> retrieveFiles(String host, int port, SftpCredentials creds,
                                         List<String> trustedHostKeys, List<String> remotePaths)
            throws Exception {
        return withSftp(host, port, creds, trustedHostKeys, sftp -> {
            List<FileFetch> out = new ArrayList<>();
            for (String remotePath : remotePaths) {
                try (InputStream in = sftp.read(remotePath)) {
                    out.add(new FileFetch(remotePath, in.readAllBytes(), null));
                } catch (Exception e) {
                    out.add(new FileFetch(remotePath, null, e.getMessage()));
                }
            }
            return out;
        });
    }

    // ── internals ────────────────────────────────────────────────────

    private interface SessionFn<T> { T apply(ClientSession session) throws Exception; }

    private interface SftpFn<T> { T apply(SftpClient sftp) throws Exception; }

    private <T> T withSftp(String host, int port, SftpCredentials creds,
                           List<String> trustedHostKeys, SftpFn<T> fn) throws Exception {
        return withSession(host, port, creds, trustedHostKeys, session -> {
            try (SftpClient sftp = SftpClientFactory.instance().createSftpClient(session)) {
                return fn.apply(sftp);
            }
        });
    }

    private <T> T withSession(String host, int port, SftpCredentials creds,
                              List<String> trustedHostKeys, SessionFn<T> fn) throws Exception {
        // MINA's security-provider registrars are suppressed once in this class's
        // static initializer (registrars=none; JDK default providers only).
        // Build the client with an explicit FilePasswordProvider so MINA's
        // ClientBuilder default (DEFAULT_FILE_PASSWORD_PROVIDER = FilePasswordProvider.EMPTY)
        // is never read: that static is null under GraalVM native (class-init
        // ordering), so setUpDefaultClient() throws "No file password provider".
        // We authenticate with the connector credentials, so any undecodable
        // ~/.ssh key is ignored rather than fatal.
        SshClient client = ClientBuilder.builder()
                .filePasswordProvider(ignorePasswordProvider())
                .build();
        client.setServerKeyVerifier(buildVerifier(trustedHostKeys));
        client.start();
        try {
            String user = creds != null && creds.username() != null ? creds.username() : "anonymous";
            try (ClientSession session = client.connect(user, host, port)
                    .verify(CONNECT_TIMEOUT).getSession()) {
                if (creds != null && creds.password() != null && !creds.password().isEmpty()) {
                    session.addPasswordIdentity(creds.password());
                }
                if (creds != null && creds.privateKey() != null && !creds.privateKey().isBlank()) {
                    for (KeyPair kp : loadKeyPairs(creds.privateKey())) {
                        session.addPublicKeyIdentity(kp);
                    }
                }
                session.auth().verify(AUTH_TIMEOUT);
                return fn.apply(session);
            }
        } catch (Exception e) {
            LOG.error("SFTP connector operation failed (diagnostic stack)", e);
            throw e;
        } finally {
            client.stop();
        }
    }

    private static ServerKeyVerifier buildVerifier(List<String> trustedHostKeys) {
        if (trustedHostKeys == null || trustedHostKeys.isEmpty()) {
            // No pinning configured: permissive (the local bundled SFTP container has an
            // ephemeral host key). See class javadoc.
            return AcceptAllServerKeyVerifier.INSTANCE;
        }
        // Pinning configured: accept only if the presented key matches a trusted entry,
        // comparing key-type + base64 blob and ignoring any trailing comment.
        return (session, remoteAddress, serverKey) -> {
            String[] presented = PublicKeyEntry.toString(serverKey).split("\\s+");
            for (String trusted : trustedHostKeys) {
                String[] t = trusted.trim().split("\\s+");
                if (t.length >= 2 && presented.length >= 2
                        && t[0].equals(presented[0]) && t[1].equals(presented[1])) {
                    return true;
                }
            }
            LOG.warn("Server host key not in TrustedHostKeys for " + remoteAddress);
            return false;
        };
    }

    private static FilePasswordProvider ignorePasswordProvider() {
        return new FilePasswordProvider() {
            @Override
            public String getPassword(SessionContext session, NamedResource resource, int retryIndex) {
                return null;
            }

            @Override
            public ResourceDecodeResult handleDecodeAttemptResult(SessionContext session, NamedResource resource,
                    int retryIndex, String password, Exception err) {
                return ResourceDecodeResult.IGNORE;
            }
        };
    }

    private Iterable<KeyPair> loadKeyPairs(String pem) throws Exception {
        try (InputStream in = new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8))) {
            Iterable<KeyPair> pairs = SecurityUtils.loadKeyPairIdentities(
                    null, NamedResource.ofName("connector-key"), in, null);
            return pairs != null ? pairs : List.of();
        }
    }
}
