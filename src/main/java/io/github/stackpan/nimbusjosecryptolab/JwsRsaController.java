package io.github.stackpan.nimbusjosecryptolab;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.text.ParseException;
import java.util.UUID;

@RestController
@RequestMapping("/jws-rsa")
public class JwsRsaController {

    private static final Logger log = LoggerFactory.getLogger(JwsRsaController.class);

    private final RSAKey privateKey;

    private final JWSSigner signer;
    private final JWSVerifier verifier;

    public JwsRsaController() throws JOSEException {
        this.privateKey = new RSAKeyGenerator(2048)
                .keyID(UUID.randomUUID().toString())
                .generate();
        log.info("Generated private key : {}", privateKey);
        var publicKey = privateKey.toPublicJWK();
        log.info("Generated public key : {}", publicKey);

        this.signer = new RSASSASigner(privateKey);
        this.verifier = new RSASSAVerifier(publicKey);
    }

    @GetMapping("/rs256/token")
    public String rs256Token() throws JOSEException {
        var header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(privateKey.getKeyID())
                .build();
        var payload = new Payload("{\"uuid\":\"%s\"}".formatted(UUID.randomUUID()));
        var jws = new JWSObject(header, payload);
        jws.sign(signer);

        return jws.serialize();
    }

    @GetMapping("/rs256/verify")
    public ResponseEntity<String> rs256Verify(@RequestParam String token) throws JOSEException, ParseException {
        var jws = JWSObject.parse(token);

        if (!jws.verify(verifier)) {
            return ResponseEntity.badRequest().build();
        }

        return ResponseEntity.ok(jws.getPayload().toString());
    }
}
