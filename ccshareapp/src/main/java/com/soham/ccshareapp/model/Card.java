package com.soham.ccshareapp.model;

import java.time.Instant;

import com.soham.ccshareapp.util.LogSafe;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Persistable;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.PostLoad;
import jakarta.persistence.PostPersist;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import jakarta.persistence.Transient;

/**
 * Implements {@link Persistable} deliberately.
 *
 * <p>{@code card_identifier} is assigned by the client, never generated, so
 * Spring Data's default "is the id null?" newness check reports every instance
 * as already-persistent and routes {@code save} through {@code merge} — a SELECT
 * followed by an UPDATE. Every payload column here is {@code updatable = false},
 * so storing a card whose identifier already exists used to update nothing at
 * all and still report success, leaving {@code CardCreationService}'s 409 branch
 * unreachable.
 *
 * <p>That was harmless while identifiers were random UUIDs and collisions never
 * happened. Identifiers are now derived from the card name, its last four
 * digits, and the passkey, so storing the same card twice is an ordinary thing
 * for a user to do — and it has to fail loudly rather than silently discard what
 * they just typed.
 */
@Entity
@Table(name = "cards")
public class Card implements Persistable<String> {

    private static final Logger logger = LoggerFactory.getLogger(Card.class);

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

    /** True only between construction and the insert; see the class comment. */
    @Transient
    private boolean unsaved;

    protected Card() {
    }

    public Card(String cardIdentifier, byte[] encryptedCcBlob, String srpVerifier, String srpSalt) {
        this.cardIdentifier = cardIdentifier;
        this.encryptedCcBlob = encryptedCcBlob.clone();
        this.srpVerifier = srpVerifier;
        this.srpSalt = srpSalt;
        this.failedAttemptCount = 0;
        this.unsaved = true;
    }

    @Override
    public String getId() {
        return cardIdentifier;
    }

    @Override
    public boolean isNew() {
        return unsaved;
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

    public int getFailedAttemptCount() {
        return failedAttemptCount;
    }

    public Instant getLockedUntil() {
        return lockedUntil;
    }

    public boolean isLocked(Instant now) {
        return lockedUntil != null && lockedUntil.isAfter(now);
    }

    public void resetFailedAttempts() {
        logger.debug("Resetting failed attempts for card {}", LogSafe.identifier(cardIdentifier));
        failedAttemptCount = 0;
        lockedUntil = null;
    }

    public void recordFailedAttempt(Instant now, int maximumAttempts, java.time.Duration lockoutDuration) {
        if (failedAttemptCount < Short.MAX_VALUE) {
            failedAttemptCount++;
        }
        logger.debug("Failed attempt recorded for card {}. Count: {}/{}",
                LogSafe.identifier(cardIdentifier), failedAttemptCount, maximumAttempts);

        if (failedAttemptCount >= maximumAttempts) {
            lockedUntil = now.plus(lockoutDuration);
            logger.warn("Card locked due to excessive failed attempts: {}. Locked until: {}",
                    LogSafe.identifier(cardIdentifier), lockedUntil);
        }
    }

    @PrePersist
    void initializeCreatedAt() {
        if (createdAt == null) {
            createdAt = Instant.now();
        }
    }

    /** Once the row exists — freshly inserted or loaded — updates must merge. */
    @PostPersist
    @PostLoad
    void markSaved() {
        unsaved = false;
    }
}
