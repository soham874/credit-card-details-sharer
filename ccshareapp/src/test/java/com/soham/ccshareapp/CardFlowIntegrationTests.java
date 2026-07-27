package com.soham.ccshareapp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import com.nimbusds.srp6.SRP6ClientCredentials;
import com.nimbusds.srp6.SRP6ClientSession;
import com.nimbusds.srp6.SRP6CryptoParams;
import com.nimbusds.srp6.SRP6VerifierGenerator;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.context.WebApplicationContext;

import static org.springframework.test.web.servlet.setup.MockMvcBuilders.webAppContextSetup;

@SpringBootTest
class CardFlowIntegrationTests {

    private static final SRP6CryptoParams SRP_CRYPTO_PARAMS = SRP6CryptoParams.getInstance(2048, "SHA-256");
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private MockMvc mockMvc;

    @Autowired
    private WebApplicationContext webApplicationContext;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    void setUp() {
        mockMvc = webAppContextSetup(webApplicationContext).build();
    }

    @Test
    void createsAndFetchesAnEncryptedCardThroughTheFrontendFlow() throws Exception {
        String cardIdentifier = java.util.UUID.randomUUID().toString();
        String passkey = "test-passkey-kept-in-browser-memory";
        String cardDetails = "{\"cardNumber\":\"4111111111111111\",\"expiry\":\"12/30\",\"cvv\":\"123\",\"pin\":\"1234\"}";
        byte[] srpSalt = randomBytes(16);
        String srpSaltHex = HexFormat.of().formatHex(srpSalt);

        byte[] encryptedCardBlob = encryptInBrowser(cardDetails, passkey, srpSalt);
        BigInteger verifier = new SRP6VerifierGenerator(SRP_CRYPTO_PARAMS)
                .generateVerifier(new BigInteger(1, srpSalt), cardIdentifier, passkey);
        String createPayload = objectMapper.writeValueAsString(new CreatePayload(
                cardIdentifier,
                Base64.getEncoder().encodeToString(encryptedCardBlob),
                verifier.toString(16),
                srpSaltHex));

        mockMvc.perform(post("/create")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(createPayload))
                .andExpect(status().isOk());

        String challengeBody = mockMvc.perform(post("/fetch")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new InitiateFetchPayload(cardIdentifier))))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();
        JsonNode challenge = objectMapper.readTree(challengeBody);
        String challengeId = challenge.required("challenge_id").asString();
        String returnedSalt = challenge.required("srp_salt").asString();
        BigInteger serverPublicEphemeral = parseHex(challenge.required("server_public_ephemeral").asString());
        assertEquals(srpSaltHex, returnedSalt);

        SRP6ClientSession clientSession = new SRP6ClientSession();
        clientSession.step1(cardIdentifier, passkey);
        SRP6ClientCredentials credentials = clientSession.step2(
                SRP_CRYPTO_PARAMS,
                parseHex(returnedSalt),
                serverPublicEphemeral);
        String proofBody = mockMvc.perform(post("/fetch")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new FetchProofPayload(
                                challengeId,
                                credentials.A.toString(16),
                                credentials.M1.toString(16)))))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();
        JsonNode fetchResult = objectMapper.readTree(proofBody);
        String encryptedBlob = fetchResult.required("encrypted_cc_blob").asString();
        String serverProof = fetchResult.required("server_proof").asString();
        assertNotNull(serverProof);
        clientSession.step3(parseHex(serverProof));

        String decryptedCardDetails = decryptInBrowser(Base64.getDecoder().decode(encryptedBlob), passkey, srpSalt);
        assertEquals(cardDetails, decryptedCardDetails);
    }

    private byte[] encryptInBrowser(String plaintext, String passkey, byte[] salt) throws Exception {
        byte[] iv = randomBytes(12);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, deriveAesKey(passkey, salt), new GCMParameterSpec(128, iv));
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        byte[] blob = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, blob, 0, iv.length);
        System.arraycopy(ciphertext, 0, blob, iv.length, ciphertext.length);
        return blob;
    }

    private String decryptInBrowser(byte[] blob, String passkey, byte[] salt) throws Exception {
        byte[] iv = java.util.Arrays.copyOfRange(blob, 0, 12);
        byte[] ciphertext = java.util.Arrays.copyOfRange(blob, 12, blob.length);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, deriveAesKey(passkey, salt), new GCMParameterSpec(128, iv));
        return new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);
    }

    private SecretKey deriveAesKey(String passkey, byte[] salt) throws Exception {
        PBEKeySpec keySpec = new PBEKeySpec(passkey.toCharArray(), salt, 600_000, 256);
        try {
            byte[] key = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(keySpec).getEncoded();
            return new SecretKeySpec(key, "AES");
        } finally {
            keySpec.clearPassword();
        }
    }

    private byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        SECURE_RANDOM.nextBytes(bytes);
        return bytes;
    }

    private BigInteger parseHex(String value) {
        String normalizedValue = value.length() % 2 == 0 ? value : "0" + value;
        return new BigInteger(1, HexFormat.of().parseHex(normalizedValue));
    }

    private record CreatePayload(String card_identifier, String encrypted_cc_blob, String srp_verifier, String srp_salt) {
    }

    private record InitiateFetchPayload(String card_identifier) {
    }

    private record FetchProofPayload(String challenge_id, String client_public_ephemeral, String client_proof) {
    }
}
