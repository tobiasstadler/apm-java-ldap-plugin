/*
   Copyright 2021 Tobias Stadler

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
 */
package co.elastic.apm.agent.java_ldap;

import co.elastic.apm.api.ElasticApm;
import co.elastic.apm.api.Outcome;
import co.elastic.apm.api.Scope;
import co.elastic.apm.api.Transaction;
import co.elastic.apm.attach.ElasticApmAttacher;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldif.LDIFReader;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockserver.client.MockServerClient;
import org.mockserver.junit.jupiter.MockServerExtension;
import org.mockserver.model.ClearType;
import org.mockserver.model.Format;

import javax.naming.Context;
import javax.naming.directory.InitialDirContext;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;
import static org.mockserver.model.JsonBody.json;

@ExtendWith(MockServerExtension.class)
public class LdapClientAdviceIT {

    private static MockServerClient MOCK_SERVER_CLIENT;

    private static InMemoryDirectoryServer LDAP_SERVER;

    @BeforeAll
    static void setUp(MockServerClient mockServerClient) throws Exception {
        MOCK_SERVER_CLIENT = mockServerClient;
        MOCK_SERVER_CLIENT.when(request("/")).respond(response().withStatusCode(200).withBody(json("{\"version\": \"7.13.0\"}")));
        MOCK_SERVER_CLIENT.when(request("/config/v1/agents")).respond(response().withStatusCode(403));
        MOCK_SERVER_CLIENT.when(request("/intake/v2/events")).respond(response().withStatusCode(200));

        InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig("dc=example,dc=com");
        config.setListenerConfigs(InMemoryListenerConfig.createLDAPConfig("test", 0));

        LDAP_SERVER = new InMemoryDirectoryServer(config);
        LDAP_SERVER.importFromLDIF(true, new LDIFReader(LdapClientAdviceIT.class.getResourceAsStream("/test.ldif")));
        LDAP_SERVER.startListening();

        Map<String, String> configuration = new HashMap<>();
        configuration.put("server_url", "http://localhost:" + mockServerClient.getPort());
        configuration.put("report_sync", "true");
        configuration.put("disable_metrics", "*");
        configuration.put("plugins_dir", "target/apm-plugins");
        configuration.put("application_packages", "co.elastic.apm.agent.java_ldap");

        ElasticApmAttacher.attach(configuration);
    }

    @AfterAll
    static void tearDown() {
        LDAP_SERVER.shutDown(true);
    }

    @BeforeEach
    void clear() {
        MOCK_SERVER_CLIENT.clear(request("/intake/v2/events"), ClearType.LOG);
    }


    @Test
    void testSuccessfulAuthentication() {
        Hashtable<String, String> environment = getEnvironment();

        Transaction transaction = ElasticApm.startTransaction();
        try (Scope scope = transaction.activate()) {
            new InitialDirContext(environment).close();
        } catch (Exception ignored) {
        } finally {
            transaction.end();
        }

        List<Map<String, Object>> spans = getSpans();
        assertEquals(1, spans.size());

        assertSpan(spans.get(0), "authenticate", Outcome.SUCCESS);
    }

    @Test
    void testUnsuccessfulAuthentication() {
        Hashtable<String, String> environment = getEnvironment();
        environment.put(Context.SECURITY_CREDENTIALS, "wrong password");

        Transaction transaction = ElasticApm.startTransaction();
        try (Scope scope = transaction.activate()) {
            new InitialDirContext(environment).close();
        } catch (Exception ignored) {
            ignored.printStackTrace();
        } finally {
            transaction.end();
        }

        List<Map<String, Object>> spans = getSpans();
        assertEquals(1, spans.size());

        assertSpan(spans.get(0), "authenticate", Outcome.FAILURE);
    }

    @Test
    void testSearch() {
        Hashtable<String, String> environment = getEnvironment();

        Transaction transaction = ElasticApm.startTransaction();
        try (Scope scope = transaction.activate()) {
            InitialDirContext context = new InitialDirContext(environment);
            context.search("dc=example,dc=com", "(&(objectClass=person)(uid=tobiasstadler))", null);
            context.close();
        } catch (Exception ignored) {
        } finally {
            transaction.end();
        }

        List<Map<String, Object>> spans = getSpans();
        assertEquals(2, spans.size());

        assertSpan(spans.get(0), "authenticate", Outcome.SUCCESS);
        assertSpan(spans.get(1), "search", Outcome.SUCCESS);
    }

    private static Hashtable<String, String> getEnvironment() {
        Hashtable<String, String> environment = new Hashtable<>();

        environment.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        environment.put(Context.PROVIDER_URL, "ldap://localhost:" + LDAP_SERVER.getListenPort());
        environment.put(Context.SECURITY_AUTHENTICATION, "simple");
        environment.put(Context.SECURITY_PRINCIPAL, "cn=Tobias Stadler,ou=Users,dc=example,dc=com");
        environment.put(Context.SECURITY_CREDENTIALS, "123456");

        return environment;
    }

    private static void assertSpan(Map<String, Object> span, String method, Outcome outcome) {
        System.out.println(span);
        assertEquals(JsonPath.read(span, "$.name"), "LDAP " + method);
        assertEquals(JsonPath.read(span, "$.type"), "external.ldap");
        assertEquals(JsonPath.read(span, "$.outcome"), outcome.name().toLowerCase(Locale.ENGLISH));
        assertEquals(JsonPath.read(span, "$.context.destination.address"), "localhost");
        assertEquals((int) JsonPath.read(span, "$.context.destination.port"), LDAP_SERVER.getListenPort());
    }


    private static List<Map<String, Object>> getSpans() {
        return getEvents()
                .flatMap(dc -> ((List<Map<String, Object>>) dc.read("$[?(@.span)].span")).stream())
                .collect(Collectors.toList());
    }

    private static Stream<DocumentContext> getEvents() {
        return ((List<String>) JsonPath.read(MOCK_SERVER_CLIENT.retrieveRecordedRequests(request("/intake/v2/events"), Format.JAVA), "$..body.rawBytes"))
                .stream()
                .map(Base64.getDecoder()::decode)
                .map(String::new)
                .flatMap(s -> Arrays.stream(s.split("\r?\n")))
                .map(JsonPath::parse);
    }
}
