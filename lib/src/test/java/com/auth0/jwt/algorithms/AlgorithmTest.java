package com.auth0.jwt.algorithms;

import com.auth0.jwt.interfaces.ECDSAKeyProvider;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.*;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

public class AlgorithmTest {


    @Test
    public void shouldThrowHMAC256InstanceWithNullSecretBytes() {
        Throwable exception = assertThrows(IllegalArgumentException.class, () -> {
            byte[] secret = null;
            Algorithm.HMAC256(secret);
        });
        assertThat(exception.getMessage(), containsString("The Secret cannot be null"));
    }

    @Test
    public void shouldThrowHMAC384InstanceWithNullSecretBytes() {
        Throwable exception = assertThrows(IllegalArgumentException.class, () -> {
            byte[] secret = null;
            Algorithm.HMAC384(secret);
        });
        assertThat(exception.getMessage(), containsString("The Secret cannot be null"));
    }

    @Test
    public void shouldThrowHMAC512InstanceWithNullSecretBytes() {
        Throwable exception = assertThrows(IllegalArgumentException.class, () -> {
            byte[] secret = null;
            Algorithm.HMAC512(secret);
        });
        assertThat(exception.getMessage(), containsString("The Secret cannot be null"));
    }

    @Test
    public void shouldThrowHMAC256InstanceWithNullSecret() {
        Throwable exception = assertThrows(IllegalArgumentException.class, () -> {
            String secret = null;
            Algorithm.HMAC256(secret);
        });
        assertThat(exception.getMessage(), containsString("The Secret cannot be null"));
    }

    @Test
    public void shouldThrowHMAC384InstanceWithNullSecret() {
        Throwable exception = assertThrows(IllegalArgumentException.class, () -> {
            String secret = null;
            Algorithm.HMAC384(secret);
        });
        assertThat(exception.getMessage(), containsString("The Secret cannot be null"));
    }

    @Test
    public void shouldThrowHMAC512InstanceWithNullSecret() {
        Throwable exception = assertThrows(IllegalArgumentException.class, () -> {
            String secret = null;
            Algorithm.HMAC512(secret);
        });
        assertThat(exception.getMessage(), containsString("The Secret cannot be null"));
    }

    @Test
    public void shouldThrowRSA256InstanceWithNullKey() {
        Throwable exception = assertThrows(IllegalArgumentException.class, () -> {
            RSAKey key = null;
            Algorithm.RSA256(key);
        });
        assertThat(exception.getMessage(), containsString("Both provided Keys cannot be null."));
    }

    @Test
    public void shouldThrowRSA256InstanceWithNullKeys() {
        Throwable exception = assertThrows(IllegalArgumentException.class, () ->
            Algorithm.RSA256(null, null));
        assertThat(exception.getMessage(), containsString("Both provided Keys cannot be null."));
    }

    @Test
    public void shouldThrowRSA256InstanceWithNullKeyProvider() {
        Throwable exception = assertThrows(IllegalArgumentException.class, () -> {
            RSAKeyProvider provider = null;
            Algorithm.RSA256(provider);
        });
        assertThat(exception.getMessage(), containsString("The Key Provider cannot be null."));
    }

    @Test
    public void shouldThrowRSA384InstanceWithNullKey() {
        Throwable exception = assertThrows(IllegalArgumentException.class, () -> {
            RSAKey key = null;
            Algorithm.RSA384(key);
        });
        assertThat(exception.getMessage(), containsString("Both provided Keys cannot be null."));
    }

    @Test
    public void shouldThrowRSA384InstanceWithNullKeys() {
        Throwable exception = assertThrows(IllegalArgumentException.class, () ->
            Algorithm.RSA384(null, null));
        assertThat(exception.getMessage(), containsString("Both provided Keys cannot be null."));
    }

    @Test
    public void shouldThrowRSA384InstanceWithNullKeyProvider() {
        Throwable exception = assertThrows(IllegalArgumentException.class, () -> {
            RSAKeyProvider provider = null;
            Algorithm.RSA384(provider);
        });
        assertThat(exception.getMessage(), containsString("The Key Provider cannot be null."));
    }

    @Test
    public void shouldThrowRSA512InstanceWithNullKey() {
        Throwable exception = assertThrows(IllegalArgumentException.class, () -> {
            RSAKey key = null;
            Algorithm.RSA512(key);
        });
        assertThat(exception.getMessage(), containsString("Both provided Keys cannot be null."));
    }

    @Test
    public void shouldThrowRSA512InstanceWithNullKeys() {
        Throwable exception = assertThrows(IllegalArgumentException.class, () ->
            Algorithm.RSA512(null, null));
        assertThat(exception.getMessage(), containsString("Both provided Keys cannot be null."));
    }

    @Test
    public void shouldThrowRSA512InstanceWithNullKeyProvider() {
        Throwable exception = assertThrows(IllegalArgumentException.class, () -> {
            RSAKeyProvider provider = null;
            Algorithm.RSA512(provider);
        });
        assertThat(exception.getMessage(), containsString("The Key Provider cannot be null."));
    }

    @Test
    public void shouldThrowECDSA256InstanceWithNullKey() {
        Throwable exception = assertThrows(IllegalArgumentException.class, () -> {
            ECKey key = null;
            Algorithm.ECDSA256(key);
        });
        assertThat(exception.getMessage(), containsString("Both provided Keys cannot be null."));
    }

    @Test
    public void shouldThrowECDSA256InstanceWithNullKeys() {
        Throwable exception = assertThrows(IllegalArgumentException.class, () ->
            Algorithm.ECDSA256(null, null));
        assertThat(exception.getMessage(), containsString("Both provided Keys cannot be null."));
    }

    @Test
    public void shouldThrowECDSA256InstanceWithNullKeyProvider() {
        Throwable exception = assertThrows(IllegalArgumentException.class, () -> {
            ECDSAKeyProvider provider = null;
            Algorithm.ECDSA256(provider);
        });
        assertThat(exception.getMessage(), containsString("The Key Provider cannot be null."));
    }

    @Test
    public void shouldThrowECDSA384InstanceWithNullKey() {
        Throwable exception = assertThrows(IllegalArgumentException.class, () -> {
            ECKey key = null;
            Algorithm.ECDSA384(key);
        });
        assertThat(exception.getMessage(), containsString("Both provided Keys cannot be null."));
    }

    @Test
    public void shouldThrowECDSA384InstanceWithNullKeys() {
        Throwable exception = assertThrows(IllegalArgumentException.class, () ->
            Algorithm.ECDSA384(null, null));
        assertThat(exception.getMessage(), containsString("Both provided Keys cannot be null."));
    }

    @Test
    public void shouldThrowECDSA384InstanceWithNullKeyProvider() {
        Throwable exception = assertThrows(IllegalArgumentException.class, () -> {
            ECDSAKeyProvider provider = null;
            Algorithm.ECDSA384(provider);
        });
        assertThat(exception.getMessage(), containsString("The Key Provider cannot be null."));
    }

    @Test
    public void shouldThrowECDSA512InstanceWithNullKey() {
        Throwable exception = assertThrows(IllegalArgumentException.class, () -> {
            ECKey key = null;
            Algorithm.ECDSA512(key);
        });
        assertThat(exception.getMessage(), containsString("Both provided Keys cannot be null."));
    }

    @Test
    public void shouldThrowECDSA512InstanceWithNullKeys() {
        Throwable exception = assertThrows(IllegalArgumentException.class, () ->
            Algorithm.ECDSA512(null, null));
        assertThat(exception.getMessage(), containsString("Both provided Keys cannot be null."));
    }

    @Test
    public void shouldThrowECDSA512InstanceWithNullKeyProvider() {
        Throwable exception = assertThrows(IllegalArgumentException.class, () -> {
            ECDSAKeyProvider provider = null;
            Algorithm.ECDSA512(provider);
        });
        assertThat(exception.getMessage(), containsString("The Key Provider cannot be null."));
    }

    @Test
    public void shouldCreateHMAC256AlgorithmWithBytes() {
        Algorithm algorithm = Algorithm.HMAC256("secret".getBytes(StandardCharsets.UTF_8));

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(HMACAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("HmacSHA256"));
        assertThat(algorithm.getName(), is("HS256"));
    }

    @Test
    public void shouldCreateHMAC384AlgorithmWithBytes() {
        Algorithm algorithm = Algorithm.HMAC384("secret".getBytes(StandardCharsets.UTF_8));

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(HMACAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("HmacSHA384"));
        assertThat(algorithm.getName(), is("HS384"));
    }

    @Test
    public void shouldCreateHMAC512AlgorithmWithBytes() {
        Algorithm algorithm = Algorithm.HMAC512("secret".getBytes(StandardCharsets.UTF_8));

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(HMACAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("HmacSHA512"));
        assertThat(algorithm.getName(), is("HS512"));
    }

    @Test
    public void shouldCreateHMAC256AlgorithmWithString() {
        Algorithm algorithm = Algorithm.HMAC256("secret");

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(HMACAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("HmacSHA256"));
        assertThat(algorithm.getName(), is("HS256"));
    }

    @Test
    public void shouldCreateHMAC384AlgorithmWithString() {
        Algorithm algorithm = Algorithm.HMAC384("secret");

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(HMACAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("HmacSHA384"));
        assertThat(algorithm.getName(), is("HS384"));
    }

    @Test
    public void shouldCreateHMAC512AlgorithmWithString() {
        Algorithm algorithm = Algorithm.HMAC512("secret");

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(HMACAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("HmacSHA512"));
        assertThat(algorithm.getName(), is("HS512"));
    }

    @Test
    public void shouldCreateRSA256AlgorithmWithPublicKey() {
        RSAKey key = mock(RSAKey.class, withSettings().extraInterfaces(RSAPublicKey.class));
        Algorithm algorithm = Algorithm.RSA256(key);

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(RSAAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("SHA256withRSA"));
        assertThat(algorithm.getName(), is("RS256"));
    }

    @Test
    public void shouldCreateRSA256AlgorithmWithPrivateKey() {
        RSAKey key = mock(RSAKey.class, withSettings().extraInterfaces(RSAPrivateKey.class));
        Algorithm algorithm = Algorithm.RSA256(key);

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(RSAAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("SHA256withRSA"));
        assertThat(algorithm.getName(), is("RS256"));
    }

    @Test
    public void shouldCreateRSA256AlgorithmWithBothKeys() {
        RSAPublicKey publicKey = mock(RSAPublicKey.class);
        RSAPrivateKey privateKey = mock(RSAPrivateKey.class);
        Algorithm algorithm = Algorithm.RSA256(publicKey, privateKey);

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(RSAAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("SHA256withRSA"));
        assertThat(algorithm.getName(), is("RS256"));
    }

    @Test
    public void shouldCreateRSA256AlgorithmWithProvider() {
        RSAKeyProvider provider = mock(RSAKeyProvider.class);
        Algorithm algorithm = Algorithm.RSA256(provider);

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(RSAAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("SHA256withRSA"));
        assertThat(algorithm.getName(), is("RS256"));
    }

    @Test
    public void shouldCreateRSA384AlgorithmWithPublicKey() {
        RSAKey key = mock(RSAKey.class, withSettings().extraInterfaces(RSAPublicKey.class));
        Algorithm algorithm = Algorithm.RSA384(key);

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(RSAAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("SHA384withRSA"));
        assertThat(algorithm.getName(), is("RS384"));
    }

    @Test
    public void shouldCreateRSA384AlgorithmWithPrivateKey() {
        RSAKey key = mock(RSAKey.class, withSettings().extraInterfaces(RSAPrivateKey.class));
        Algorithm algorithm = Algorithm.RSA384(key);

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(RSAAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("SHA384withRSA"));
        assertThat(algorithm.getName(), is("RS384"));
    }

    @Test
    public void shouldCreateRSA384AlgorithmWithBothKeys() {
        RSAPublicKey publicKey = mock(RSAPublicKey.class);
        RSAPrivateKey privateKey = mock(RSAPrivateKey.class);
        Algorithm algorithm = Algorithm.RSA384(publicKey, privateKey);

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(RSAAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("SHA384withRSA"));
        assertThat(algorithm.getName(), is("RS384"));
    }

    @Test
    public void shouldCreateRSA384AlgorithmWithProvider() {
        RSAKeyProvider provider = mock(RSAKeyProvider.class);
        Algorithm algorithm = Algorithm.RSA384(provider);

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(RSAAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("SHA384withRSA"));
        assertThat(algorithm.getName(), is("RS384"));
    }

    @Test
    public void shouldCreateRSA512AlgorithmWithPublicKey() {
        RSAKey key = mock(RSAKey.class, withSettings().extraInterfaces(RSAPublicKey.class));
        Algorithm algorithm = Algorithm.RSA512(key);

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(RSAAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("SHA512withRSA"));
        assertThat(algorithm.getName(), is("RS512"));
    }

    @Test
    public void shouldCreateRSA512AlgorithmWithPrivateKey() {
        RSAKey key = mock(RSAKey.class, withSettings().extraInterfaces(RSAPrivateKey.class));
        Algorithm algorithm = Algorithm.RSA512(key);

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(RSAAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("SHA512withRSA"));
        assertThat(algorithm.getName(), is("RS512"));
    }

    @Test
    public void shouldCreateRSA512AlgorithmWithBothKeys() {
        RSAPublicKey publicKey = mock(RSAPublicKey.class);
        RSAPrivateKey privateKey = mock(RSAPrivateKey.class);
        Algorithm algorithm = Algorithm.RSA512(publicKey, privateKey);

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(RSAAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("SHA512withRSA"));
        assertThat(algorithm.getName(), is("RS512"));
    }

    @Test
    public void shouldCreateRSA512AlgorithmWithProvider() {
        RSAKeyProvider provider = mock(RSAKeyProvider.class);
        Algorithm algorithm = Algorithm.RSA512(provider);

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(RSAAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("SHA512withRSA"));
        assertThat(algorithm.getName(), is("RS512"));
    }

    @Test
    public void shouldCreateECDSA256AlgorithmWithPublicKey() {
        ECKey key = mock(ECKey.class, withSettings().extraInterfaces(ECPublicKey.class));
        Algorithm algorithm = Algorithm.ECDSA256(key);

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(ECDSAAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("SHA256withECDSA"));
        assertThat(algorithm.getName(), is("ES256"));
    }

    @Test
    public void shouldCreateECDSA256AlgorithmWithPrivateKey() {
        ECKey key = mock(ECKey.class, withSettings().extraInterfaces(ECPrivateKey.class));
        Algorithm algorithm = Algorithm.ECDSA256(key);

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(ECDSAAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("SHA256withECDSA"));
        assertThat(algorithm.getName(), is("ES256"));
    }

    @Test
    public void shouldCreateECDSA256AlgorithmWithBothKeys() {
        ECPublicKey publicKey = mock(ECPublicKey.class);
        ECPrivateKey privateKey = mock(ECPrivateKey.class);
        Algorithm algorithm = Algorithm.ECDSA256(publicKey, privateKey);

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(ECDSAAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("SHA256withECDSA"));
        assertThat(algorithm.getName(), is("ES256"));
    }

    @Test
    public void shouldCreateECDSA256AlgorithmWithProvider() {
        ECDSAKeyProvider provider = mock(ECDSAKeyProvider.class);
        Algorithm algorithm = Algorithm.ECDSA256(provider);

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(ECDSAAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("SHA256withECDSA"));
        assertThat(algorithm.getName(), is("ES256"));
    }

    @Test
    public void shouldCreateECDSA384AlgorithmWithPublicKey() {
        ECKey key = mock(ECKey.class, withSettings().extraInterfaces(ECPublicKey.class));
        Algorithm algorithm = Algorithm.ECDSA384(key);

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(ECDSAAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("SHA384withECDSA"));
        assertThat(algorithm.getName(), is("ES384"));
    }

    @Test
    public void shouldCreateECDSA384AlgorithmWithPrivateKey() {
        ECKey key = mock(ECKey.class, withSettings().extraInterfaces(ECPrivateKey.class));
        Algorithm algorithm = Algorithm.ECDSA384(key);

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(ECDSAAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("SHA384withECDSA"));
        assertThat(algorithm.getName(), is("ES384"));
    }

    @Test
    public void shouldCreateECDSA384AlgorithmWithBothKeys() {
        ECPublicKey publicKey = mock(ECPublicKey.class);
        ECPrivateKey privateKey = mock(ECPrivateKey.class);
        Algorithm algorithm = Algorithm.ECDSA384(publicKey, privateKey);

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(ECDSAAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("SHA384withECDSA"));
        assertThat(algorithm.getName(), is("ES384"));
    }

    @Test
    public void shouldCreateECDSA384AlgorithmWithProvider() {
        ECDSAKeyProvider provider = mock(ECDSAKeyProvider.class);
        Algorithm algorithm = Algorithm.ECDSA384(provider);

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(ECDSAAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("SHA384withECDSA"));
        assertThat(algorithm.getName(), is("ES384"));
    }

    @Test
    public void shouldCreateECDSA512AlgorithmWithPublicKey() {
        ECKey key = mock(ECKey.class, withSettings().extraInterfaces(ECPublicKey.class));
        Algorithm algorithm = Algorithm.ECDSA512(key);

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(ECDSAAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("SHA512withECDSA"));
        assertThat(algorithm.getName(), is("ES512"));
    }

    @Test
    public void shouldCreateECDSA512AlgorithmWithPrivateKey() {
        ECKey key = mock(ECKey.class, withSettings().extraInterfaces(ECPrivateKey.class));
        Algorithm algorithm = Algorithm.ECDSA512(key);

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(ECDSAAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("SHA512withECDSA"));
        assertThat(algorithm.getName(), is("ES512"));
    }

    @Test
    public void shouldCreateECDSA512AlgorithmWithBothKeys() {
        ECPublicKey publicKey = mock(ECPublicKey.class);
        ECPrivateKey privateKey = mock(ECPrivateKey.class);
        Algorithm algorithm = Algorithm.ECDSA512(publicKey, privateKey);

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(ECDSAAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("SHA512withECDSA"));
        assertThat(algorithm.getName(), is("ES512"));
    }

    @Test
    public void shouldCreateECDSA512AlgorithmWithProvider() {
        ECDSAKeyProvider provider = mock(ECDSAKeyProvider.class);
        Algorithm algorithm = Algorithm.ECDSA512(provider);

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(ECDSAAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("SHA512withECDSA"));
        assertThat(algorithm.getName(), is("ES512"));
    }

    @Test
    public void shouldCreateNoneAlgorithm() {
        Algorithm algorithm = Algorithm.none();

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(NoneAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("none"));
        assertThat(algorithm.getName(), is("none"));
    }

    @Test
    public void shouldForwardHeaderPayloadSignatureToSiblingSignMethodForBackwardsCompatibility() throws Exception {
        Algorithm algorithm = mock(Algorithm.class);

        ArgumentCaptor<byte[]> contentCaptor = ArgumentCaptor.forClass(byte[].class);

        byte[] header = new byte[]{0x00, 0x01, 0x02};
        byte[] payload = new byte[]{0x04, 0x05, 0x06};

        byte[] signature = new byte[]{0x10, 0x11, 0x12};
        when(algorithm.sign(any(byte[].class), any(byte[].class))).thenCallRealMethod();
        when(algorithm.sign(contentCaptor.capture())).thenReturn(signature);

        byte[] sign = algorithm.sign(header, payload);

        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        bout.write(header);
        bout.write('.');
        bout.write(payload);
        
        assertThat(sign, is(signature));
        assertThat(contentCaptor.getValue(), is(bout.toByteArray()));
    }
}