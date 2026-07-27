package com.soham.ccshareapp.card;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;

@Entity
@Table(name = "cards")
public class Card {

    @Id
    @Column(name = "card_identifier", nullable = false, updatable = false, length = 36)
    private String cardIdentifier;

    @Column(name = "encrypted_cc_blob", nullable = false, updatable = false, length = 512)
    private byte[] encryptedCcBlob;

    @Column(name = "srp_verifier", nullable = false, updatable = false, length = 512)
    private String srpVerifier;

    @Column(name = "srp_salt", nullable = false, updatable = false, length = 64)
    private String srpSalt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "failed_attempt_count", nullable = false)
    private short failedAttemptCount;

    @Column(name = "locked_until")
    private Instant lockedUntil;

    protected Card() {
    }

    public Card(String cardIdentifier, byte[] encryptedCcBlob, String srpVerifier, String srpSalt) {
        this.cardIdentifier = cardIdentifier;
        this.encryptedCcBlob = encryptedCcBlob.clone();
        this.srpVerifier = srpVerifier;
        this.srpSalt = srpSalt;
        this.failedAttemptCount = 0;
    }

    public byte[] getEncryptedCcBlob() {
        return encryptedCcBlob.clone();
    }

    public String getSrpVerifier() {
        return srpVerifier;
    }

    public String getSrpSalt() {
        return srpSalt;
    }

    public boolean isLocked(Instant now) {
        return lockedUntil != null && lockedUntil.isAfter(now);
    }

    public void resetFailedAttempts() {
        failedAttemptCount = 0;
        lockedUntil = null;
    }

    public void recordFailedAttempt(Instant now, int maximumAttempts, java.time.Duration lockoutDuration) {
        if (failedAttemptCount < Short.MAX_VALUE) {
            failedAttemptCount++;
        }
        if (failedAttemptCount >= maximumAttempts) {
            lockedUntil = now.plus(lockoutDuration);
        }
    }

    @PrePersist
    void initializeCreatedAt() {
        if (createdAt == null) {
            createdAt = Instant.now();
        }
    }
}
