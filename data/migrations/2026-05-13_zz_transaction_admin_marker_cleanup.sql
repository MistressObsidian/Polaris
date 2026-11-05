-- Permanently rewrite legacy admin-labelled transaction history values
-- to neutral user-facing labels.

UPDATE transactions
SET reference = regexp_replace(reference, '^ADMCRT-', 'OPEN-', 'i')
WHERE reference ~* '^ADMCRT-';

UPDATE transactions
SET reference = regexp_replace(reference, '^ADMIN-', 'TXN-', 'i')
WHERE reference ~* '^ADMIN-';

UPDATE transactions
SET description = 'Opening balance'
WHERE description ~* 'new user opening balance';

UPDATE transactions
SET description = 'Balance adjustment'
WHERE description ~* 'manual balance adjustment';

UPDATE transactions
SET description = 'Transfer'
WHERE description ~* 'transfer initiated for';

UPDATE transactions
SET description = NULLIF(BTRIM(regexp_replace(description, '(^|[^[:alnum:]_])admin([^[:alnum:]_]|$)', ' ', 'ig')), '')
WHERE description ~* '(^|[^[:alnum:]_])admin([^[:alnum:]_]|$)';

UPDATE transfers
SET description = 'Transfer'
WHERE description ~* 'transfer initiated for';

UPDATE transfers
SET description = NULLIF(BTRIM(regexp_replace(description, '(^|[^[:alnum:]_])admin([^[:alnum:]_]|$)', ' ', 'ig')), '')
WHERE description ~* '(^|[^[:alnum:]_])admin([^[:alnum:]_]|$)';