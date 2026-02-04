package com.auth0.jwt.algorithms;

import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.hamcrest.MatcherAssert.assertThat;

public class NoneAlgorithmTest {

    @Test
    public void shouldPassNoneVerification() {
        Algorithm algorithm = Algorithm.none();
        String jwt = "eyJhbGciOiJub25lIiwiY3R5IjoiSldUIn0.eyJpc3MiOiJhdXRoMCJ9.";
        algorithm.verify(JWT.decode(jwt));
    }

    @Test
    public void shouldFailNoneVerificationWhenTokenHasTwoParts() {
        Throwable exception = assertThrows(JWTDecodeException.class, () -> {
            String jwt = "eyJhbGciOiJub25lIiwiY3R5IjoiSldUIn0.eyJpc3MiOiJhdXRoMCJ9";
            Algorithm algorithm = Algorithm.none();
            algorithm.verify(JWT.decode(jwt));
        });
        assertThat(exception.getMessage(), containsString("The token was expected to have 3 parts, but got 2."));
    }

    @Test
    public void shouldFailNoneVerificationWhenSignatureIsPresent() {
        Throwable exception = assertThrows(SignatureVerificationException.class, () -> {
            String jwt = "eyJhbGciOiJub25lIiwiY3R5IjoiSldUIn0.eyJpc3MiOiJhdXRoMCJ9.Ox-WRXRaGAuWt2KfPvWiGcCrPqZtbp_4OnQzZXaTfss";
            Algorithm algorithm = Algorithm.none();
            algorithm.verify(JWT.decode(jwt));
        });
        assertThat(exception.getMessage(), containsString("The Token's Signature resulted invalid when verified using the Algorithm: none"));
    }

    @Test
    public void shouldReturnNullSigningKeyId() {
        assertThat(Algorithm.none().getSigningKeyId(), is(nullValue()));
    }

    @Test
    public void shouldThrowWhenSignatureNotValidBase64() {
        Throwable exception = assertThrows(SignatureVerificationException.class, () -> {

            String jwt = "eyJhbGciOiJub25lIiwiY3R5IjoiSldUIn0.eyJpc3MiOiJhdXRoMCJ9.Ox-WRXRaGAuWt2KfPvW+iGcCrPqZtbp_4OnQzZXaTfss";
            Algorithm algorithm = Algorithm.none();
            algorithm.verify(JWT.decode(jwt));
        });
        assertThat(exception.getCause(), isA(IllegalArgumentException.class));
    }
}