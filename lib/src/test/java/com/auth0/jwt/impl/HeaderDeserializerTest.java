package com.auth0.jwt.impl;

import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.Header;
import tools.jackson.core.JsonParser;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.NullNode;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.io.StringReader;
import java.util.HashMap;
import java.util.Map;

import static com.auth0.jwt.impl.JWTParser.getDefaultObjectMapper;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class HeaderDeserializerTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();
    private HeaderDeserializer deserializer;

    @Before
    public void setUp() {
        deserializer = new HeaderDeserializer();
    }

    @Test
    public void shouldThrowOnNullTree() throws Exception {
        exception.expect(JWTDecodeException.class);
        exception.expectMessage("Parsing the Header's JSON resulted on a Null map");

        HeaderDeserializer deserializer = new HeaderDeserializer();
        JsonParser parser = mock(JsonParser.class);
        DeserializationContext context = mock(DeserializationContext.class);

        when(context.readValue(eq(parser), any(TypeReference.class))).thenReturn(null);

        deserializer.deserialize(parser, context);
    }


    @Test
    public void shouldNotRemoveKnownPublicClaimsFromTree() throws Exception {
        String headerJSON = "{\n" +
                "  \"alg\": \"HS256\",\n" +
                "  \"typ\": \"jws\",\n" +
                "  \"cty\": \"content\",\n" +
                "  \"kid\": \"key\",\n" +
                "  \"roles\": \"admin\"\n" +
                "}";
        StringReader reader = new StringReader(headerJSON);
        ObjectMapper mapper = getDefaultObjectMapper();
        JsonParser jsonParser = mapper.createParser(reader);

        Header header = deserializer.deserialize(jsonParser, mapper._deserializationContext());

        assertThat(header, is(notNullValue()));
        assertThat(header.getAlgorithm(), is("HS256"));
        assertThat(header.getType(), is("jws"));
        assertThat(header.getContentType(), is("content"));
        assertThat(header.getKeyId(), is("key"));

        assertThat(header.getHeaderClaim("roles").asString(), is("admin"));
        assertThat(header.getHeaderClaim("alg").asString(), is("HS256"));
        assertThat(header.getHeaderClaim("typ").asString(), is("jws"));
        assertThat(header.getHeaderClaim("cty").asString(), is("content"));
        assertThat(header.getHeaderClaim("kid").asString(), is("key"));
    }

    @Test
    public void shouldGetNullStringWhenParsingNullNode() {
        Map<String, JsonNode> tree = new HashMap<>();
        NullNode node = NullNode.getInstance();
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
        JsonNode node = mapper.getNodeFactory().textNode("something here");
        tree.put("key", node);

        String text = deserializer.getString(tree, "key");
        assertThat(text, is(notNullValue()));
        assertThat(text, is("something here"));
    }
}
