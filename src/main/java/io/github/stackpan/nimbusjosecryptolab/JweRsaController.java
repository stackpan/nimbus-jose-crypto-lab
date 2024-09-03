package io.github.stackpan.nimbusjosecryptolab;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
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
@RequestMapping("/jwe-rsa")
public class JweRsaController {

    private static final Logger log = LoggerFactory.getLogger(JweRsaController.class);
    private final RSAKey privateKey;
    private final RSAKey publicKey;

    private final JWEEncrypter encrypter;
    private final JWEDecrypter decrypter;

    public JweRsaController() throws JOSEException {
        this.privateKey = new RSAKeyGenerator(2048)
                .keyID(UUID.randomUUID().toString())
                .generate();
        log.info("Generated private key : {}", privateKey);
        this.publicKey = privateKey.toPublicJWK();
        log.info("Generated public key : {}", publicKey);

        this.encrypter = new RSAEncrypter(publicKey);
        this.decrypter = new RSADecrypter(privateKey);
    }

    @GetMapping("/rsa-oaep-256/token")
    public String rsaOaep256Token() throws JOSEException {
        var header = new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM);

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

        var jwt = new EncryptedJWT(header, claimsSet);
        jwt.encrypt(encrypter);

        return jwt.serialize();
    }

    @GetMapping("/rsa-oaep-256/verify")
    public ResponseEntity<Object> rsaOaep256Verify(@RequestParam String token) throws JOSEException, ParseException {
        var jwt = EncryptedJWT.parse(token);

        var badRequest = ResponseEntity.badRequest().build();
        try {
            jwt.decrypt(decrypter);
        } catch (JOSEException e) {
            return badRequest;
        }

        var claimsSet = jwt.getJWTClaimsSet();

        if (!claimsSet.getAudience().contains("self")) {
            return badRequest;
        }

        if (claimsSet.getExpirationTime().before(Date.from(Instant.now()))) {
            return badRequest;
        }

        return ResponseEntity.ok(jwt.getPayload().toString());
    }
}
