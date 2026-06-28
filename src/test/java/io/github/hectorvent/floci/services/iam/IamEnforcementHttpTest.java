package io.github.hectorvent.floci.services.iam;

import io.github.hectorvent.floci.services.iam.model.AccessKey;
import io.github.hectorvent.floci.testing.RestAssuredJsonUtils;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.restassured.response.Response;
import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

/**
 * End-to-end IAM enforcement over the HTTP request path. With enforcement enabled
 * via a scoped {@link TestProfile}, a seeded explicit-deny policy makes a request
 * signed with that principal's access key return 403 AccessDenied, while the
 * default "test" root credential bypasses enforcement. The profile keeps
 * enforcement OFF for the rest of the suite (which relies on the permissive
 * default), so this does not turn the compatibility suite red.
 */
@QuarkusTest
@TestProfile(IamEnforcementHttpTest.EnforcementOn.class)
class IamEnforcementHttpTest {

    public static final class EnforcementOn implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of("floci.services.iam.enforcement-enabled", "true");
        }
    }

    private static final String CT = "application/x-amz-json-1.0";

    @Inject
    IamService iamService;

    @BeforeEach
    void configure() {
        RestAssuredJsonUtils.configureAwsContentTypes();
    }

    private static String authHeader(String accessKeyId, String service) {
        return "AWS4-HMAC-SHA256 Credential=" + accessKeyId
                + "/20260626/us-east-1/" + service + "/aws4_request, "
                + "SignedHeaders=host;x-amz-target, Signature=0000";
    }

    @Test
    void explicitDenyPolicyBlocksRequestWith403() {
        String user = "deny-user-" + System.nanoTime();
        iamService.createUser(user, "/");
        iamService.putUserPolicy(user, "deny-ddb-put", """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Deny","Action":"dynamodb:PutItem","Resource":"*"}
            ]}""");
        AccessKey key = iamService.createAccessKey(user);

        given()
                .contentType(CT)
                .header("X-Amz-Target", "DynamoDB_20120810.PutItem")
                .header("Authorization", authHeader(key.getAccessKeyId(), "dynamodb"))
                .body("{\"TableName\":\"t\",\"Item\":{}}")
                .when().post("/")
                .then().statusCode(403)
                .body("__type", equalTo("AccessDeniedException"));
    }

    @Test
    void rootTestCredentialBypassesEnforcement() {
        // The default "test" access key is the root/admin stand-in and must pass
        // through even with enforcement enabled (keeps normal local traffic working).
        Response resp = given()
                .contentType(CT)
                .header("X-Amz-Target", "DynamoDB_20120810.PutItem")
                .header("Authorization", authHeader("test", "dynamodb"))
                .body("{\"TableName\":\"t\",\"Item\":{}}")
                .when().post("/");
        assertNotEquals(403, resp.statusCode());
    }
}
