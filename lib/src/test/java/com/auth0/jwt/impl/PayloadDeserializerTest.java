package com.auth0.jwt.impl;

import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.Payload;
import tools.jackson.core.JsonParser;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import org.hamcrest.collection.IsCollectionWithSize;
import org.hamcrest.core.IsIterableContaining;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.StringReader;
import java.time.Instant;
import java.util.*;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class PayloadDeserializerTest {
    private PayloadDeserializer deserializer;

    private ObjectMapper objectMapper;

    @BeforeEach
    public void setUp() {
        objectMapper = new ObjectMapper();
        deserializer = new PayloadDeserializer();
    }

    @Test
    public void shouldThrowOnNullTree() {
        Throwable exception = assertThrows(JWTDecodeException.class, () -> {

            JsonParser parser = mock(JsonParser.class);
            DeserializationContext context = mock(DeserializationContext.class);

            when(context.readValue(eq(parser), any(TypeReference.class))).thenReturn(null);

            deserializer.deserialize(parser, context);
        });
        assertThat(exception.getMessage(), containsString("Parsing the Payload's JSON resulted on a Null map"));
    }

    @Test
    public void shouldThrowWhenParsingArrayWithObjectValue() {
        Throwable exception = assertThrows(JWTDecodeException.class, () -> {

            JsonNode jsonNode = objectMapper.readTree("{\"some\" : \"random\", \"properties\" : \"inside\"}");
            Map<String, JsonNode> tree = new HashMap<>();
            ArrayNode arrNode = objectMapper.createArrayNode();
            arrNode.add(jsonNode);
            tree.put("key", arrNode);

            deserializer.getStringOrArray(objectMapper._deserializationContext(), tree, "key");
        });
        assertThat(exception.getMessage(), containsString("Couldn't map the Claim's array contents to String"));
    }

    @Test
    public void shouldNotRemoveKnownPublicClaimsFromTree() throws Exception {
        String payloadJSON = "{\n" +
                "  \"iss\": \"auth0\",\n" +
                "  \"sub\": \"emails\",\n" +
                "  \"aud\": \"users\",\n" +
                "  \"iat\": 10101010,\n" +
                "  \"exp\": 11111111,\n" +
                "  \"nbf\": 10101011,\n" +
                "  \"jti\": \"idid\",\n" +
                "  \"roles\":\"admin\" \n" +
                "}";
        StringReader reader = new StringReader(payloadJSON);
        JsonParser jsonParser = objectMapper.createParser(reader);

        Payload payload = deserializer.deserialize(jsonParser, objectMapper._deserializationContext());

        assertThat(payload, is(notNullValue()));
        assertThat(payload.getIssuer(), is("auth0"));
        assertThat(payload.getSubject(), is("emails"));
        assertThat(payload.getAudience(), is(IsIterableContaining.hasItem("users")));
        assertThat(payload.getIssuedAt().getTime(), is(10101010L * 1000));
        assertThat(payload.getExpiresAt().getTime(), is(11111111L * 1000));
        assertThat(payload.getNotBefore().getTime(), is(10101011L * 1000));
        assertThat(payload.getIssuedAtAsInstant().getEpochSecond(), is(10101010L));
        assertThat(payload.getExpiresAtAsInstant().getEpochSecond(), is(11111111L));
        assertThat(payload.getNotBeforeAsInstant().getEpochSecond(), is(10101011L));
        assertThat(payload.getId(), is("idid"));

        assertThat(payload.getClaim("roles").asString(), is("admin"));
        assertThat(payload.getClaim("iss").asString(), is("auth0"));
        assertThat(payload.getClaim("sub").asString(), is("emails"));
        assertThat(payload.getClaim("aud").asString(), is("users"));
        assertThat(payload.getClaim("iat").asDouble(), is(10101010D));
        assertThat(payload.getClaim("exp").asDouble(), is(11111111D));
        assertThat(payload.getClaim("nbf").asDouble(), is(10101011D));
        assertThat(payload.getClaim("jti").asString(), is("idid"));
    }

    @Test
    public void shouldGetStringArrayWhenParsingArrayNode() {
        Map<String, JsonNode> tree = new HashMap<>();
        ArrayNode arrNode = objectMapper.createArrayNode();
        arrNode.add(objectMapper.getNodeFactory().stringNode("one"));
        arrNode.add(objectMapper.getNodeFactory().stringNode("two"));
        tree.put("key", arrNode);

        List<String> values = deserializer.getStringOrArray(objectMapper._deserializationContext(), tree, "key");
        assertThat(values, is(notNullValue()));
        assertThat(values, is(IsCollectionWithSize.hasSize(2)));
        assertThat(values, is(IsIterableContaining.hasItems("one", "two")));
    }

    @Test
    public void shouldGetStringArrayWhenParsingTextNode() {
        Map<String, JsonNode> tree = new HashMap<>();
        ObjectMapper mapper = new ObjectMapper();
        JsonNode textNode = mapper.getNodeFactory().stringNode("something");
        tree.put("key", textNode);

        DeserializationContext context = mock(DeserializationContext.class);
        List<String> values = deserializer.getStringOrArray(context, tree, "key");
        assertThat(values, is(notNullValue()));
        assertThat(values, is(IsCollectionWithSize.hasSize(1)));
        assertThat(values, is(IsIterableContaining.hasItems("something")));
    }

    @Test
    public void shouldGetEmptyStringInArrayWhenParsingEmptyTextNode() {
        Map<String, JsonNode> tree = new HashMap<>();
        ObjectMapper mapper = new ObjectMapper();
        JsonNode textNode = mapper.getNodeFactory().stringNode("");
        tree.put("key", textNode);

        DeserializationContext context = mock(DeserializationContext.class);
        List<String> values = deserializer.getStringOrArray(context, tree, "key");
        assertThat(values, is(notNullValue()));
        assertThat(values, is(IsIterableContaining.hasItem("")));
    }

    @Test
    public void shouldGetNullArrayWhenParsingNullNode() {
        Map<String, JsonNode> tree = new HashMap<>();
        ObjectMapper mapper = new ObjectMapper();
        JsonNode node = mapper.getNodeFactory().nullNode();
        tree.put("key", node);

        DeserializationContext context = mock(DeserializationContext.class);
        List<String> values = deserializer.getStringOrArray(context, tree, "key");
        assertThat(values, is(nullValue()));
    }

    @Test
    public void shouldGetNullArrayWhenParsingNullNodeValue() {
        Map<String, JsonNode> tree = new HashMap<>();
        tree.put("key", null);

        DeserializationContext context = mock(DeserializationContext.class);
        List<String> values = deserializer.getStringOrArray(context, tree, "key");
        assertThat(values, is(nullValue()));
    }

    @Test
    public void shouldGetNullArrayWhenParsingNonArrayOrTextNode() {
        Map<String, JsonNode> tree = new HashMap<>();
        ObjectMapper mapper = new ObjectMapper();
        JsonNode node = mapper.getNodeFactory().numberNode(456789);
        tree.put("key", node);

        DeserializationContext context = mock(DeserializationContext.class);
        List<String> values = deserializer.getStringOrArray(context, tree, "key");
        assertThat(values, is(nullValue()));
    }

    @Test
    public void shouldGetNullInstantWhenParsingNullNode() {
        Map<String, JsonNode> tree = new HashMap<>();
        ObjectMapper mapper = new ObjectMapper();
        JsonNode node = mapper.getNodeFactory().nullNode();
        tree.put("key", node);

        Instant instant = deserializer.getInstantFromSeconds(tree, "key");
        assertThat(instant, is(nullValue()));
    }

    @Test
    public void shouldGetNullInstantWhenParsingNull() {
        Map<String, JsonNode> tree = new HashMap<>();
        tree.put("key", null);

        Instant instant  = deserializer.getInstantFromSeconds(tree, "key");
        assertThat(instant, is(nullValue()));
    }

    @Test
    public void shouldThrowWhenParsingNonNumericNode() {
        Throwable exception = assertThrows(JWTDecodeException.class, () -> {

            Map<String, JsonNode> tree = new HashMap<>();
            ObjectMapper mapper = new ObjectMapper();
            JsonNode node = mapper.getNodeFactory().stringNode("123456789");
            tree.put("key", node);

            deserializer.getInstantFromSeconds(tree, "key");
        });
        assertThat(exception.getMessage(), containsString("The claim 'key' contained a non-numeric date value."));
    }

    @Test
    public void shouldGetInstantWhenParsingNumericNode() {
        Map<String, JsonNode> tree = new HashMap<>();
        long seconds = 1478627949 / 1000;
        ObjectMapper mapper = new ObjectMapper();
        JsonNode node = mapper.getNodeFactory().numberNode(seconds);
        tree.put("key", node);

        Instant instant = deserializer.getInstantFromSeconds(tree, "key");
        assertThat(instant, is(notNullValue()));
        assertThat(instant.toEpochMilli(), is(seconds * 1000));
    }


    @Test
    public void shouldGetLargeInstantWhenParsingNumericNode() {
        Map<String, JsonNode> tree = new HashMap<>();
        long seconds = Integer.MAX_VALUE + 10000L;
        ObjectMapper mapper = new ObjectMapper();
        JsonNode node = mapper.getNodeFactory().numberNode(seconds);
        tree.put("key", node);

        Instant instant = deserializer.getInstantFromSeconds(tree, "key");
        assertThat(instant, is(notNullValue()));
        assertThat(instant.toEpochMilli(), is(seconds * 1000));
        assertThat(instant.toEpochMilli(), is(2147493647L * 1000));
    }

    @Test
    public void shouldGetNullStringWhenParsingNullNode() {
        Map<String, JsonNode> tree = new HashMap<>();
        ObjectMapper mapper = new ObjectMapper();
        JsonNode node = mapper.getNodeFactory().nullNode();
        tree.put("key", node);

        String text = deserializer.getString(tree, "key");
        assertThat(text, is(nullValue()));
    }

    @Test
    public void shouldGetNullStringWhenParsingNull() {
        Map<String, JsonNode> tree = new HashMap<>();
        tree.put("key", null);

        String text = deserializer.getString(tree, "key");
        assertThat(text, is(nullValue()));
    }

    @Test
    public void shouldGetStringWhenParsingTextNode() {
        Map<String, JsonNode> tree = new HashMap<>();
        ObjectMapper mapper = new ObjectMapper();
        JsonNode node = mapper.getNodeFactory().stringNode("something here");
        tree.put("key", node);

        String text = deserializer.getString(tree, "key");
        assertThat(text, is(notNullValue()));
        assertThat(text, is("something here"));
    }

}
