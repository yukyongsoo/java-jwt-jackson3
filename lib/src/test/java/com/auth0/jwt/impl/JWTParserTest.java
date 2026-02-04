package com.auth0.jwt.impl;

import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.Header;
import com.auth0.jwt.interfaces.Payload;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.ObjectReader;
import tools.jackson.databind.SerializationFeature;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static com.auth0.jwt.impl.JWTParser.getDefaultObjectMapper;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class JWTParserTest {
    private JWTParser parser;

    @BeforeEach
    public void setUp() {
        parser = new JWTParser();
    }

    @Test
    public void shouldGetDefaultObjectMapper() {
        ObjectMapper mapper = getDefaultObjectMapper();
        assertThat(mapper, is(notNullValue()));
        assertThat(mapper, is(instanceOf(ObjectMapper.class)));
        assertThat(mapper.isEnabled(SerializationFeature.FAIL_ON_EMPTY_BEANS), is(false));
    }

    @Test
    public void shouldAddDeserializers() {
        tools.jackson.databind.json.JsonMapper.Builder builder = tools.jackson.databind.json.JsonMapper.builder();
        JWTParser.addDeserializers(builder);
        tools.jackson.databind.ObjectMapper mapper = builder.build();
        assertThat(mapper, is(notNullValue()));
    }

    @Test
    public void shouldParsePayload() throws Exception {
        ObjectMapper mapper = mock(ObjectMapper.class);
        ObjectReader reader = mock(ObjectReader.class);
        when(mapper.readerFor(Payload.class)).thenReturn(reader);
        JWTParser parser = new JWTParser(mapper);
        parser.parsePayload("{}");

        verify(reader).readValue("{}");
    }

    @Test
    public void shouldThrowOnInvalidPayload() {
        String jsonPayload = "{{";
        Throwable exception = assertThrows(JWTDecodeException.class, () -> {
            Payload payload = parser.parsePayload(jsonPayload);
            assertThat(payload, is(nullValue()));
        });
        assertThat(exception.getMessage(), containsString(String.format("The string '%s' doesn't have a valid JSON format.", jsonPayload)));
    }

    @Test
    public void shouldParseHeader() throws Exception {
        ObjectMapper mapper = mock(ObjectMapper.class);
        ObjectReader reader = mock(ObjectReader.class);
        when(mapper.readerFor(Header.class)).thenReturn(reader);
        JWTParser parser = new JWTParser(mapper);
        parser.parseHeader("{}");

        verify(reader).readValue("{}");
    }

    @Test
    public void shouldThrowOnInvalidHeader() {
        String jsonHeader = "}}";
        Throwable exception = assertThrows(JWTDecodeException.class, () -> {
            Header header = parser.parseHeader(jsonHeader);
            assertThat(header, is(nullValue()));
        });
        assertThat(exception.getMessage(), containsString(String.format("The string '%s' doesn't have a valid JSON format.", jsonHeader)));
    }

    @Test
    public void shouldThrowWhenConvertingHeaderIfNullJson() {
        Throwable exception = assertThrows(JWTDecodeException.class, () ->
            parser.parseHeader(null));
        assertThat(exception.getMessage(), containsString("The string 'null' doesn't have a valid JSON format."));
    }

    @Test
    public void shouldThrowWhenConvertingHeaderFromInvalidJson() {
        Throwable exception = assertThrows(JWTDecodeException.class, () ->
            parser.parseHeader("}{"));
        assertThat(exception.getMessage(), containsString("The string '}{' doesn't have a valid JSON format."));
    }

    @Test
    public void shouldThrowWhenConvertingPayloadIfNullJson() {
        Throwable exception = assertThrows(JWTDecodeException.class, () ->
            parser.parsePayload(null));
        assertThat(exception.getMessage(), containsString("The string 'null' doesn't have a valid JSON format."));
    }

    @Test
    public void shouldThrowWhenConvertingPayloadFromInvalidJson() {
        Throwable exception = assertThrows(JWTDecodeException.class, () ->
            parser.parsePayload("}{"));
        assertThat(exception.getMessage(), containsString("The string '}{' doesn't have a valid JSON format."));
    }
}
