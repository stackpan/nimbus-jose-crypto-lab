package io.github.stackpan.nimbusjosecryptolab;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.junit.jupiter.api.Test;

import java.util.UUID;

public class JwsWithRsaTest {

    @Test
    void rs256RsaPkcs1() throws JOSEException {
        RSAKey privateKey = new RSAKeyGenerator(2048)
                .keyID(UUID.randomUUID().toString())
                .generate();
        RSAKey publicKey = privateKey.toPublicJWK();

        JWSSigner jwsSigner = new RSASSASigner(privateKey);

        JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(privateKey.getKeyID()).build();
        Payload payload = new Payload("{\"message\":\"Hello World!\"}");
        JWSObject jwsObject = new JWSObject(jwsHeader, payload);
        jwsObject.sign(jwsSigner);

        System.out.printf("Private Key: %s\n", privateKey);
        System.out.printf("Public Key: %s\n", publicKey);
        System.out.printf("Token: %s\n", jwsObject.serialize());
    }
}
