package io.github.stackpan.nimbusjosecryptolab;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

@RestController
@RequestMapping("/jwt-rsa")
public class JwtRsaController {

    private static final Logger log = LoggerFactory.getLogger(JwtRsaController.class);

    private final RSAKey privateKey;

    private final JWSSigner signer;
    private final JWSVerifier verifier;

    public JwtRsaController() throws JOSEException {
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
                .type(JOSEObjectType.JWT)
                .build();

        var now = Instant.now();
        var claimsSet = new JWTClaimsSet.Builder()
                .subject(UUID.randomUUID().toString())
                .jwtID(UUID.randomUUID().toString())
                .issuer("self")
                .audience("self")
                .issueTime(Date.from(now))
                .notBeforeTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(60)))
                .build();

        var jwt = new SignedJWT(header, claimsSet);
        jwt.sign(signer);

        return jwt.serialize();
    }

    @GetMapping("/rs256/verify")
    public ResponseEntity<Object> rs256Verify(@RequestParam String token) throws JOSEException, ParseException {
        var jws = SignedJWT.parse(token);

        var badRequest = ResponseEntity.badRequest().build();

        if (!jws.verify(verifier)) {
            return badRequest;
        }

        var claimsSet = jws.getJWTClaimsSet();

        if (!claimsSet.getAudience().contains("self")) {
            return badRequest;
        }

        if (claimsSet.getExpirationTime().before(Date.from(Instant.now()))) {
            return badRequest;
        }

        return ResponseEntity.ok(jws.getPayload().toString());
    }

}
