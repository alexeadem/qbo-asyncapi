package com.jhooq.springbootcommandlinerunner;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jwt.*;
import com.nimbusds.jose.util.*;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;


@SpringBootApplication
public class EcdhjweApplication implements CommandLineRunner {

    private static Logger LOG = LoggerFactory
            .getLogger(EcdhjweApplication.class);

    static ECKey exposedJWK = generateECKeyJwk();

    public static void main(String[] args) {

        SpringApplication.run(EcdhjweApplication.class, args);
    }

    @Override
    public void run(String... args) {
        LOG.info("EXECUTING : command line runner");

        try {
            System.out.println("X: \n" + exposedJWK.toECPublicKey().getW().getAffineX());
            System.out.println("Y: \n" + exposedJWK.toECPublicKey().getW().getAffineY());
            System.out.println("D: \n" + exposedJWK.toECPrivateKey().getS());
        } catch (JOSEException e) {
            e.printStackTrace();
        }

        System.out.println("======================== Encrypting ================================");
        String encryptedRequest = null;
        try {
            encryptedRequest = encryptJWE("test string", exposedJWK.toECPublicKey());
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println("Encrypted Requested::: " + encryptedRequest);

        System.out.println("======================== Decrypting Request ================================");

        /* test */
        encryptedRequest = "eyJhbGciOiJFQ0RILUVTIiwgImVuYyI6IkEyNTZDQkMtSFM1MTIiLCAiZXBrIjp7ImNydiI6IlAtNTIxIiwia3R5IjoiRUMiLCJ4IjoiQUVEUHA1cGhIYjBHYXJlenFPR1YzY0wzbWlFSjBHakNyVTVKdUxkYnBsYmpZQnZJMkpuRlpiMmU5LWhmMExucTkzVXlxc2RZamxpWkEwQ1NqSWxGOGZGQyIsInkiOiJBWDJQN0NiREJ0a2ZYd2w0VGdXSW4wRlUxNmgtTFU3Y29wTk1IZG9DX2ZOdm1aazRhLWs1QllEa3VjeDVic3pqNW9QZFhFQmlvV3RYMnlGRXcyTFV1YTUtIn0KfQ..avaewt02iopyC7l8wtT6DQ.H0c1d5lzighc9WUuh7MfhccggUpviXAW5jpiW0pK7vX4x9owQwi86d2RFLQ2MIGh.p9qusgTS-Vr4LExYs0VD3WOMx8VYx5Djr-EpwT5Co5Y";

        String decryptedDetails = null;
        try {
            decryptedDetails = decryptJWE(encryptedRequest, exposedJWK.toECPrivateKey());
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println("Decrypted Request:::" + decryptedDetails);
    }

    //private static String encryptJWE(JSONObject payload, ECPublicKey ecPublicKey) throws Exception {
    private static String encryptJWE(String payload, ECPublicKey ecPublicKey) throws Exception {
        // Build JWE header
        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A256GCM)
                .build();

        // Build JWE Object
        JWEObject jweObjectClient = new JWEObject(header, new Payload(payload));

        // Set Public Key, Encrypt
        ECDHEncrypter encrypter = new ECDHEncrypter(ecPublicKey);
        encrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
        jweObjectClient.encrypt(encrypter);
        return jweObjectClient.serialize();
    }

    private static String decryptJWE(String vcnRequestJWE, ECPrivateKey ecPrivateKey) throws Exception {
        // Parse JWE & validate headers
        JWEObject jweObject = EncryptedJWT.parse(vcnRequestJWE);

        // Set PrivateKey and Decrypt
        ECDHDecrypter decrypter = new ECDHDecrypter(ecPrivateKey);
        decrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
        jweObject.decrypt(decrypter);

        return jweObject.getPayload().toString();
    }

    public static ECKey generateECKeyJwk() {
        try {
            // Generate EC key pair with P-521 curve

            String x = "AMu-cWn4gmkQiCAJMeW4BfZUAhPwAA3rROnw6nGUk8hl3bvV7gKKng2Eov6oxTvg70kulH6Nbq2wvJbAzyAjnPlT";
            String y = "Ab7VgSfOzG-7IgRF6ffUn5E0J43eDL8_vFtFtP7RihVgNBMUeZzo0yaskfx59SdqnL8q24wEHSTp4dDUxNal3kQ1";
            String d = "AVuTcFe_AJetnzt2xYQu2M505A3YNoAiHgh7JlkbFJq7H3UNjmaEhawPiK0AU8IoimyfoN4cCSlF087u1_Cytqw7";

            return new ECKey.Builder(Curve.P_521, new Base64URL(x), new Base64URL(y))
                    .d(new Base64URL(d))
                    .build();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

}
