package io.github.stackpan.nimbusjosecryptolab;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.security.SecureRandom;
import java.text.ParseException;
import java.util.Base64;
import java.util.UUID;

@RestController
@RequestMapping("/jws-hmac")
public class JwsHmacController {

    private static final Logger log = LoggerFactory.getLogger(JwsHmacController.class);

    private final JWSSigner signer;
    private final JWSVerifier verifier;

    public JwsHmacController() throws JOSEException {
        byte[] secret = new byte[32];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(secret);
        log.info("Generated secret: {}", Base64.getEncoder().encodeToString(secret));
        signer = new MACSigner(secret);
        verifier = new MACVerifier(secret);
    }

    @GetMapping("/hs256/token")
    public String hs256Token() throws JOSEException {
        var header = new JWSHeader(JWSAlgorithm.HS256);
        var payload = new Payload("{\"uuid\":\"%s\"}".formatted(UUID.randomUUID()));
        var jws = new JWSObject(header, payload);

        jws.sign(signer);
        return jws.serialize();
    }

    @GetMapping("/hs256/verify")
    public ResponseEntity<String> hs256Verify(@RequestParam String token) throws ParseException, JOSEException {
        var jws = JWSObject.parse(token);

        if (!jws.verify(verifier)) {
            return ResponseEntity.badRequest().build();
        }

        return ResponseEntity.ok(jws.getPayload().toString());
    }
}
