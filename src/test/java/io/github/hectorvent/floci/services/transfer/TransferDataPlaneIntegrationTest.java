package io.github.hectorvent.floci.services.transfer;

import io.github.hectorvent.floci.services.s3.S3Service;
import io.github.hectorvent.floci.services.s3.model.S3Object;
import io.github.hectorvent.floci.services.secretsmanager.SecretsManagerService;
import io.github.hectorvent.floci.testing.RestAssuredJsonUtils;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.Response;
import jakarta.inject.Inject;
import org.apache.sshd.common.file.virtualfs.VirtualFileSystemFactory;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.sftp.server.SftpSubsystemFactory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * AWS Transfer connector data plane against a real embedded SFTP server: TestConnection,
 * StartDirectoryListing (writes a listing object to S3), StartFileTransfer (pulls SFTP
 * files into S3), and ListFileTransferResults. This is the SFTP→S3 reconciliation path
 * HomeBinder drives — the connector's MINA sshd client pulls from the embedded server
 * and writes into the engine's own in-process S3.
 */
@QuarkusTest
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class TransferDataPlaneIntegrationTest {

    private static final String CT = "application/x-amz-json-1.1";
    private static final String PREFIX = "TransferService.";
    private static final String BUCKET = "transfer-dataplane-test";
    private static final byte[] FILE_BODY = "psu,report,2026\n1,2,3\n".getBytes();

    private static SshServer sshd;
    private static int sftpPort;

    private static String connectorId;
    private static String transferId;
    private static String listingOutputFile;

    @Inject
    SecretsManagerService secretsManager;

    @Inject
    S3Service s3;

    @BeforeAll
    static void startSftp() throws Exception {
        RestAssuredJsonUtils.configureAwsContentTypes();

        Path root = Files.createTempDirectory("floci-sftp-fixture");
        Path reports = Files.createDirectories(root.resolve("Core_PSU_Reports"));
        Files.write(reports.resolve("report1.csv"), FILE_BODY);

        sshd = SshServer.setUpDefaultServer();
        sshd.setPort(0);
        sshd.setKeyPairProvider(new SimpleGeneratorHostKeyProvider());
        sshd.setPasswordAuthenticator((username, password, session) ->
                "spectrum".equals(username) && "pass".equals(password));
        sshd.setSubsystemFactories(List.of(new SftpSubsystemFactory.Builder().build()));
        sshd.setFileSystemFactory(new VirtualFileSystemFactory(root));
        sshd.start();
        sftpPort = sshd.getPort();
    }

    @AfterAll
    static void stopSftp() throws Exception {
        if (sshd != null) {
            sshd.stop(true);
        }
    }

    private static Response call(String action, String body) {
        return given().contentType(CT).header("X-Amz-Target", PREFIX + action)
                .body(body).when().post("/");
    }

    @Test
    @Order(1)
    void setUpSecretAndConnector() {
        secretsManager.createSecret("local/spectrum",
                "{\"Username\":\"spectrum\",\"Password\":\"pass\"}",
                null, null, null, null, "us-east-1");

        Response resp = call("CreateConnector",
                "{\"Url\":\"sftp://127.0.0.1:" + sftpPort + "\","
                        + "\"AccessRole\":\"arn:aws:iam::000000000000:role/transfer-access\","
                        + "\"SftpConfig\":{\"UserSecretId\":\"local/spectrum\"}}");
        resp.then().statusCode(200).body("ConnectorId", notNullValue());
        connectorId = resp.jsonPath().getString("ConnectorId");
    }

    @Test
    @Order(2)
    void testConnectionSucceeds() {
        call("TestConnection", "{\"ConnectorId\":\"" + connectorId + "\"}")
                .then().statusCode(200)
                .body("Status", equalTo("OK"))
                .body("SftpConnectionDetails.HostKey", notNullValue());
    }

    @Test
    @Order(3)
    void startDirectoryListingWritesToS3() {
        Response resp = call("StartDirectoryListing",
                "{\"ConnectorId\":\"" + connectorId + "\","
                        + "\"RemoteDirectoryPath\":\"/Core_PSU_Reports\","
                        + "\"OutputDirectoryPath\":\"/" + BUCKET + "/connector_output\"}");
        resp.then().statusCode(200)
                .body("ListingId", notNullValue())
                .body("OutputFileName", notNullValue());
        listingOutputFile = resp.jsonPath().getString("OutputFileName");

        S3Object listing = s3.getObject(BUCKET, "connector_output/" + listingOutputFile);
        String json = new String(listing.getData());
        assertTrue(json.contains("report1.csv"), "listing should reference the remote file");
    }

    @Test
    @Order(4)
    void startFileTransferPullsIntoS3() {
        Response resp = call("StartFileTransfer",
                "{\"ConnectorId\":\"" + connectorId + "\","
                        + "\"RetrieveFilePaths\":[\"/Core_PSU_Reports/report1.csv\"],"
                        + "\"LocalDirectoryPath\":\"/" + BUCKET + "/reconciliation\"}");
        resp.then().statusCode(200).body("TransferId", notNullValue());
        transferId = resp.jsonPath().getString("TransferId");

        S3Object pulled = s3.getObject(BUCKET, "reconciliation/report1.csv");
        assertArrayEquals(FILE_BODY, pulled.getData());
    }

    @Test
    @Order(5)
    void listFileTransferResultsReportsCompleted() {
        call("ListFileTransferResults",
                "{\"ConnectorId\":\"" + connectorId + "\",\"TransferId\":\"" + transferId + "\"}")
                .then().statusCode(200)
                .body("FileTransferResults[0].FilePath", equalTo("/Core_PSU_Reports/report1.csv"))
                .body("FileTransferResults[0].StatusCode", equalTo("COMPLETED"));
    }
}
