package io.github.stackpan.nimbusjosecryptolab;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.text.ParseException;

public class JwsWithHmacTest {

    @Test
    void jsonHelloWorldMessageHs256() throws JOSEException, ParseException {
        var random = new SecureRandom();
        byte[] secret = new byte[32];
        random.nextBytes(secret);

        JWSSigner signer = new MACSigner(secret);

        var jwsHeader = new JWSHeader(JWSAlgorithm.HS256);
        var jwsPayload = new Payload("{\"message\":\"Hello World!\"}");
        var jwsObject = new JWSObject(jwsHeader, jwsPayload);

        jwsObject.sign(signer);

        System.out.println(jwsObject.serialize());
    }

    @Test
    @Disabled
    void jsonHelloWorldMessageHs256WithVerifier() throws JOSEException, ParseException {
        SecureRandom random = new SecureRandom();
        byte[] sharedSecret = new byte[32];
        random.nextBytes(sharedSecret);

        JWSSigner signer = new MACSigner(sharedSecret);

        JWSHeader jwsHeader = new JWSHeader(JWSAlgorithm.HS256);
        Payload payload = new Payload("{\"message\":\"Hello World!\"}");
        JWSObject producerJwsObject = new JWSObject(jwsHeader, payload);

        producerJwsObject.sign(signer);

        String token = producerJwsObject.serialize();
        System.out.printf("Secret: %s\n", new String(sharedSecret));
        System.out.printf("Token: %s\n", token);

        JWSObject consumerJwsObject = JWSObject.parse(token);

//        byte[] falseSharedSecret = new byte[32];
//        random.nextBytes(falseSharedSecret);
//        JWSVerifier falseVerifier = new MACVerifier(falseSharedSecret);
//        System.out.printf("With falseVerifier result: %s\n", consumerJwsObject.verify(falseVerifier));

        JWSVerifier correctVerifier = new MACVerifier(sharedSecret);
        System.out.printf("With correctVerifier result: %s\n", consumerJwsObject.verify(correctVerifier));
    }

    @Test
    void jsonHelloWorldMessageHs384() throws JOSEException, ParseException {
        var random = new SecureRandom();
        byte[] secret = new byte[48];
        random.nextBytes(secret);

        JWSSigner signer = new MACSigner(secret);

        var jwsHeader = new JWSHeader(JWSAlgorithm.HS384);
        var jwsPayload = new Payload("{\"message\":\"Hello World!\"}");
        var jwsObject = new JWSObject(jwsHeader, jwsPayload);

        jwsObject.sign(signer);

        System.out.println(jwsObject.serialize());
    }

    @Test
    void jsonHelloWorldMessageHs512() throws JOSEException {
        var random = new SecureRandom();
        byte[] secret = new byte[64];
        random.nextBytes(secret);

        JWSSigner signer = new MACSigner(secret);

        var jwsHeader = new JWSHeader(JWSAlgorithm.HS512);
        var jwsPayload = new Payload("{\"message\":\"Hello World!\"}");
        var jwsObject = new JWSObject(jwsHeader, jwsPayload);

        jwsObject.sign(signer);

        System.out.println(jwsObject.serialize());
    }
}
