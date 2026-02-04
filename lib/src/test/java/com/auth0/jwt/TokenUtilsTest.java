package com.auth0.jwt;

import com.auth0.jwt.exceptions.JWTDecodeException;
import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.hamcrest.MatcherAssert.assertThat;

public class TokenUtilsTest {

    @Test
    public void toleratesEmptyFirstPart() {
        String token = ".eyJpc3MiOiJhdXRoMCJ9.W1mx_Y0hbAMbPmfW9whT605AAcxB7REFuJiDAHk2Sdc";
        String[] parts = TokenUtils.splitToken(token);

        assertThat(parts, is(notNullValue()));
        assertThat(parts, is(arrayWithSize(3)));
        assertThat(parts[0], is(""));
        assertThat(parts[1], is("eyJpc3MiOiJhdXRoMCJ9"));
        assertThat(parts[2], is("W1mx_Y0hbAMbPmfW9whT605AAcxB7REFuJiDAHk2Sdc"));
    }

    @Test
    public void toleratesEmptySecondPart() {
        String token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0..W1mx_Y0hbAMbPmfW9whT605AAcxB7REFuJiDAHk2Sdc";
        String[] parts = TokenUtils.splitToken(token);

        assertThat(parts, is(notNullValue()));
        assertThat(parts, is(arrayWithSize(3)));
        assertThat(parts[0], is("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"));
        assertThat(parts[1], is(""));
        assertThat(parts[2], is("W1mx_Y0hbAMbPmfW9whT605AAcxB7REFuJiDAHk2Sdc"));
    }

    @Test
    public void shouldSplitToken() {
        String token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJhdXRoMCJ9.W1mx_Y0hbAMbPmfW9whT605AAcxB7REFuJiDAHk2Sdc";
        String[] parts = TokenUtils.splitToken(token);

        assertThat(parts, is(notNullValue()));
        assertThat(parts, is(arrayWithSize(3)));
        assertThat(parts[0], is("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"));
        assertThat(parts[1], is("eyJpc3MiOiJhdXRoMCJ9"));
        assertThat(parts[2], is("W1mx_Y0hbAMbPmfW9whT605AAcxB7REFuJiDAHk2Sdc"));
    }

    @Test
    public void shouldSplitTokenWithEmptySignature() {
        String token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJhdXRoMCJ9.";
        String[] parts = TokenUtils.splitToken(token);

        assertThat(parts, is(notNullValue()));
        assertThat(parts, is(arrayWithSize(3)));
        assertThat(parts[0], is("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"));
        assertThat(parts[1], is("eyJpc3MiOiJhdXRoMCJ9"));
        assertThat(parts[2], is(emptyString()));
    }

    @Test
    public void shouldThrowOnSplitTokenWithMoreThan3Parts() {
        Throwable exception = assertThrows(JWTDecodeException.class, () -> {
            String token = "this.has.four.parts";
            TokenUtils.splitToken(token);
        });
        assertThat(exception.getMessage(), containsString("The token was expected to have 3 parts, but got > 3."));
    }

    @Test
    public void shouldThrowOnSplitTokenWithNoParts() {
        Throwable exception = assertThrows(JWTDecodeException.class, () -> {
            String token = "notajwt";
            TokenUtils.splitToken(token);
        });
        assertThat(exception.getMessage(), containsString("The token was expected to have 3 parts, but got 0."));
    }

    @Test
    public void shouldThrowOnSplitTokenWith2Parts() {
        Throwable exception = assertThrows(JWTDecodeException.class, () -> {
            String token = "two.parts";
            TokenUtils.splitToken(token);
        });
        assertThat(exception.getMessage(), containsString("The token was expected to have 3 parts, but got 2."));
    }

    @Test
    public void shouldThrowOnSplitTokenWithNullValue() {
        Throwable exception = assertThrows(JWTDecodeException.class, () ->
            TokenUtils.splitToken(null));
        assertThat(exception.getMessage(), containsString("The token is null."));
    }
}