-- `card_label` existed so `/fetch` step 1 could name the card before the passkey
-- was entered (LLD §4.3). Identifiers are now derived client-side from the card
-- name, its last four digits, and the passkey, so the user already knows which
-- card they are unlocking and the label is carried inside `encrypted_cc_blob`
-- instead. Keeping a plaintext copy would leak every nickname to anyone with
-- database access and buy nothing.
ALTER TABLE cards DROP COLUMN card_label;
