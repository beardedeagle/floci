package io.github.hectorvent.floci.services.transfer;

import jakarta.enterprise.context.ApplicationScoped;
import org.jboss.logging.Logger;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.ClientBuilder;
import org.apache.sshd.client.keyverifier.AcceptAllServerKeyVerifier;
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
 * <p>Host-key verification is intentionally permissive (AcceptAll): this is a local
 * emulator data-plane surface, not a security boundary — see docs/CONTRACT.md.
 */
@ApplicationScoped
public class SftpConnectorClient {

    private static final Logger LOG = Logger.getLogger(SftpConnectorClient.class);

    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(15);
    private static final Duration AUTH_TIMEOUT = Duration.ofSeconds(15);

    public record SftpCredentials(String username, String password, String privateKey) {}

    public record RemoteEntry(String name, long size, long modifiedEpochMillis, boolean directory) {}

    /** Connect and return the server host key in OpenSSH format (e.g. "ssh-rsa AAAA..."). */
    public String fetchHostKey(String host, int port, SftpCredentials creds) throws Exception {
        return withSession(host, port, creds, session ->
                PublicKeyEntry.toString(session.getServerKey()));
    }

    /** List a remote directory (excludes "." and ".."). */
    public List<RemoteEntry> listDirectory(String host, int port, SftpCredentials creds, String remotePath)
            throws Exception {
        return withSftp(host, port, creds, sftp -> {
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

    /** Retrieve the full contents of a remote file. */
    public byte[] retrieveFile(String host, int port, SftpCredentials creds, String remotePath)
            throws Exception {
        return withSftp(host, port, creds, sftp -> {
            try (InputStream in = sftp.read(remotePath)) {
                return in.readAllBytes();
            }
        });
    }

    // ── internals ────────────────────────────────────────────────────

    private interface SessionFn<T> { T apply(ClientSession session) throws Exception; }

    private interface SftpFn<T> { T apply(SftpClient sftp) throws Exception; }

    private <T> T withSftp(String host, int port, SftpCredentials creds, SftpFn<T> fn) throws Exception {
        return withSession(host, port, creds, session -> {
            try (SftpClient sftp = SftpClientFactory.instance().createSftpClient(session)) {
                return fn.apply(sftp);
            }
        });
    }

    private <T> T withSession(String host, int port, SftpCredentials creds, SessionFn<T> fn) throws Exception {
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
        // host key is negotiated instead. Must be set before the first SshClient touch.
        System.setProperty("org.apache.sshd.security.registrars", "none");
        // Build the client with an explicit FilePasswordProvider so MINA's
        // ClientBuilder default (DEFAULT_FILE_PASSWORD_PROVIDER = FilePasswordProvider.EMPTY)
        // is never read: that static is null under GraalVM native (class-init
        // ordering), so setUpDefaultClient() throws "No file password provider".
        // We authenticate with the connector credentials, so any undecodable
        // ~/.ssh key is ignored rather than fatal.
        SshClient client = ClientBuilder.builder()
                .filePasswordProvider(ignorePasswordProvider())
                .build();
        client.setServerKeyVerifier(AcceptAllServerKeyVerifier.INSTANCE);
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
        try (InputStream in = new ByteArrayInputStream(pem.getBytes())) {
            Iterable<KeyPair> pairs = SecurityUtils.loadKeyPairIdentities(
                    null, NamedResource.ofName("connector-key"), in, null);
            return pairs != null ? pairs : List.of();
        }
    }
}
