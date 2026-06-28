package io.github.hectorvent.floci.services.transfer;

import io.github.hectorvent.floci.testing.RestAssuredJsonUtils;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.Response;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * AWS Transfer Family connector management-plane flow over the AWS JSON 1.1 wire
 * protocol: connector create / describe / list / delete, plus validation and
 * not-found paths. These are the control-plane ops HomeBinder's reconciliation
 * calls (stock Floci returned UnknownOperationException for connector ops).
 */
@QuarkusTest
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class TransferConnectorIntegrationTest {

    private static final String CT = "application/x-amz-json-1.1";
    private static final String PREFIX = "TransferService.";

    private static String connectorId;

    @BeforeAll
    static void configure() {
        RestAssuredJsonUtils.configureAwsContentTypes();
    }

    private static Response call(String action, String body) {
        return given().contentType(CT).header("X-Amz-Target", PREFIX + action)
                .body(body).when().post("/");
    }

    @Test
    @Order(1)
    void createConnector() {
        Response resp = call("CreateConnector",
                "{\"Url\":\"sftp://partner.example.com\","
                        + "\"AccessRole\":\"arn:aws:iam::000000000000:role/transfer-access\","
                        + "\"SftpConfig\":{\"UserSecretId\":\"local/spectrum\","
                        + "\"TrustedHostKeys\":[\"ssh-rsa AAAAB3example\"]}}");
        resp.then().statusCode(200)
                .body("ConnectorId", notNullValue())
                .body("ConnectorId", startsWith("c-"));
        connectorId = resp.jsonPath().getString("ConnectorId");
    }

    @Test
    @Order(2)
    void describeConnector() {
        call("DescribeConnector", "{\"ConnectorId\":\"" + connectorId + "\"}")
                .then().statusCode(200)
                .body("Connector.ConnectorId", equalTo(connectorId))
                .body("Connector.Url", equalTo("sftp://partner.example.com"))
                .body("Connector.SftpConfig.UserSecretId", equalTo("local/spectrum"))
                .body("Connector.Arn", notNullValue());
    }

    @Test
    @Order(3)
    void listConnectorsContainsCreated() {
        call("ListConnectors", "{}")
                .then().statusCode(200)
                .body("Connectors.find { it.ConnectorId == '" + connectorId + "' }.Url",
                        equalTo("sftp://partner.example.com"));
    }

    @Test
    @Order(4)
    void deleteConnector() {
        call("DeleteConnector", "{\"ConnectorId\":\"" + connectorId + "\"}")
                .then().statusCode(200);
    }

    @Test
    @Order(5)
    void describeMissingConnectorReturnsNotFound() {
        call("DescribeConnector", "{\"ConnectorId\":\"c-00000000000000000\"}")
                .then().statusCode(404)
                .body("__type", equalTo("ResourceNotFoundException"));
    }

    @Test
    @Order(6)
    void createConnectorWithoutUrlFails() {
        call("CreateConnector", "{\"AccessRole\":\"arn:aws:iam::000000000000:role/x\"}")
                .then().statusCode(400)
                .body("__type", equalTo("InvalidRequestException"));
    }

    @Test
    @Order(7)
    void listConnectorsOmitsNextTokenWhenPageExactlyExhaustsResults() {
        // Regression: NextToken must not be emitted when the page size equals
        // maxResults but there are no further results (else clients paginate into
        // an empty page).
        call("CreateConnector",
                "{\"Url\":\"sftp://partner.example.com\","
                        + "\"AccessRole\":\"arn:aws:iam::000000000000:role/transfer-access\","
                        + "\"SftpConfig\":{\"UserSecretId\":\"local/spectrum\"}}")
                .then().statusCode(200);
        int total = call("ListConnectors", "{\"MaxResults\":1000}")
                .jsonPath().getList("Connectors").size();
        Response r = call("ListConnectors", "{\"MaxResults\":" + total + "}");
        r.then().statusCode(200);
        assertNull(r.jsonPath().get("NextToken"),
                "no NextToken when the page exactly exhausts results");
    }

    @Test
    @Order(8)
    void listConnectorsRejectsOutOfRangeMaxResults() {
        // MaxResults must be 1-1000; 0/negative previously tripped the over-fetch
        // pagination into an IndexOutOfBoundsException.
        call("ListConnectors", "{\"MaxResults\":0}")
                .then().statusCode(400)
                .body("__type", equalTo("InvalidRequestException"));
    }
}
