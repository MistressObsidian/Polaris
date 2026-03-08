/**
 * bank.js
 * Database abstraction layer for Polaris fintech operations
 * Uses email-primary-key schema with user_email as the canonical identity
 */

let pool = null;

/**
 * Initialize the bank module with a database pool instance
 * @param {Pool} postgresPool - pg.Pool instance from server.js
 */
export function initBank(postgresPool) {
  pool = postgresPool;
}

/**
 * General query helper
 * @param {string} text - SQL query text
 * @param {array} params - Query parameters
 * @returns {Promise<{rows, rowCount}>} Query result
 */
export async function query(text, params = []) {
  if (!pool) throw new Error("Bank module not initialized");
  return pool.query(text, params);
}

// ==============================
// Users
// ==============================

/**
 * Create a new user account
 * @param {object} params - {user_email, fullname, password_hash, phone, accountname}
 * @returns {Promise<{user_email, available_balance}>}
 */
export async function createUser({ user_email, fullname, password_hash, phone, accountname }) {
  const result = await query(
    `INSERT INTO users (user_email, fullname, password_hash, phone, accountname)
     VALUES ($1, $2, $3, $4, $5)
     RETURNING user_email, available_balance`,
    [user_email, fullname, password_hash, phone, accountname]
  );
  return result.rows[0];
}

/**
 * Get full user profile
 * @param {string} user_email - User email (case-insensitive)
 * @returns {Promise<{user_email, fullname, phone, accountname, available_balance, suspended}>}
 */
export async function getUser(user_email) {
  const result = await query(
    `SELECT user_email, fullname, phone, accountname, available_balance, suspended
     FROM users WHERE user_email = $1`,
    [user_email]
  );
  return result.rows[0];
}

/**
 * Get user's available balance
 * @param {string} user_email - User email
 * @returns {Promise<number>} Available balance or 0
 */
export async function getUserBalance(user_email) {
  const result = await query(
    `SELECT available_balance FROM users WHERE user_email = $1`,
    [user_email]
  );
  return result.rows[0]?.available_balance || 0;
}

/**
 * Update user's available balance
 * @param {string} user_email - User email
 * @param {number} balanceChange - Amount to add/subtract (can be negative)
 * @returns {Promise<{available_balance}>}
 */
export async function updateUserBalance(user_email, balanceChange) {
  const result = await query(
    `UPDATE users SET available_balance = available_balance + $1 WHERE user_email = $2
     RETURNING available_balance`,
    [balanceChange, user_email]
  );
  return result.rows[0];
}

// ==============================
// Accounts
// ==============================

/**
 * Get or create user's account
 * @param {string} user_email - User email
 * @param {string} type - Account type (default: 'available')
 * @returns {Promise<{id, user_email, type, balance, available}>}
 */
export async function getOrCreateAccount(user_email, type = 'available') {
  const result = await query(
    `SELECT id, user_email, type, balance, available FROM accounts
     WHERE user_email = $1 AND type = $2`,
    [user_email, type]
  );
  
  if (result.rows[0]) return result.rows[0];
  
  // Create if doesn't exist
  const newAccount = await query(
    `INSERT INTO accounts (user_email, type) VALUES ($1, $2)
     RETURNING id, user_email, type, balance, available`,
    [user_email, type]
  );
  return newAccount.rows[0];
}

/**
 * Get account by ID
 * @param {string} account_id - Account UUID
 * @returns {Promise<{id, user_email, type, balance, available}>}
 */
export async function getAccount(account_id) {
  const result = await query(
    `SELECT id, user_email, type, balance, available FROM accounts WHERE id = $1`,
    [account_id]
  );
  return result.rows[0];
}

// ==============================
// Transactions
// ==============================

/**
 * Add a transaction (credit/debit) and update balances atomically
 * @param {object} params - {user_email, type, direction, amount, description, reference}
 * @returns {Promise<{id, balance_after}>}
 */
export async function addTransaction({ user_email, type, direction, amount, description, reference }) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Get account for this user
    const accRes = await client.query(
      `SELECT id FROM accounts WHERE user_email = $1 AND type = 'available'`,
      [user_email]
    );
    if (!accRes.rows[0]) throw new Error('No account found for user');
    const account_id = accRes.rows[0].id;

    // Insert transaction
    const status = 'completed';
    const txRes = await client.query(
      `INSERT INTO transactions (user_email, account_id, type, direction, amount, description, reference, status, balance_after)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, (SELECT available FROM accounts WHERE id = $2) + CASE WHEN $4='credit' THEN $5 ELSE -$5 END)
       RETURNING id, balance_after`,
      [user_email, account_id, type, direction, amount, description, reference, status]
    );

    // Update account balance
    const balanceChange = direction === 'credit' ? amount : -amount;
    await client.query(
      `UPDATE accounts SET available = available + $1 WHERE id = $2`,
      [balanceChange, account_id]
    );

    // Update user balance
    await client.query(
      `UPDATE users SET available_balance = available_balance + $1 WHERE user_email = $2`,
      [balanceChange, user_email]
    );

    await client.query('COMMIT');
    return txRes.rows[0];
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

/**
 * Get transactions for a user
 * @param {string} user_email - User email
 * @param {number} limit - Max records (default: 100)
 * @returns {Promise<array>} Array of transactions
 */
export async function getTransactions(user_email, limit = 100) {
  const result = await query(
    `SELECT id, type, direction, amount, description, reference, status, balance_after, created_at
     FROM transactions
     WHERE user_email = $1
     ORDER BY created_at DESC
     LIMIT $2`,
    [user_email, limit]
  );
  return result.rows;
}

/**
 * Get single transaction with details
 * @param {string} transaction_id - Transaction UUID
 * @param {string} user_email - User email (for validation)
 * @returns {Promise<object>} Transaction with user details
 */
export async function getTransactionWithDetails(transaction_id, user_email) {
  const result = await query(
    `SELECT t.id, t.user_email, t.account_id, t.type, t.direction, t.amount, 
            t.description, t.reference, t.status, t.balance_after, t.created_at,
            u.fullname, (SELECT available FROM accounts WHERE id = t.account_id) as account_balance
     FROM transactions t
     JOIN users u ON u.user_email = t.user_email
     WHERE t.id = $1 AND t.user_email = $2`,
    [transaction_id, user_email]
  );
  return result.rows[0];
}

// ==============================
// Transfers
// ==============================

/**
 * Make internal transfer (between two users)
 * @param {object} params - {sender_email, recipient_email, amount, description, method}
 * @returns {Promise<{success}>}
 */
export async function makeInternalTransfer({ sender_email, recipient_email, amount, description, method = 'wire' }) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Verify recipient exists
    const recipRes = await client.query(
      `SELECT user_email FROM users WHERE user_email = $1`,
      [recipient_email]
    );
    if (!recipRes.rows[0]) throw new Error('Recipient not found');

    // Insert transfer record
    await client.query(
      `INSERT INTO transfers (user_email, recipient_email, method, amount, description, status)
       VALUES ($1, $2, $3, $4, $5, 'completed')`,
      [sender_email, recipient_email, method, amount, description]
    );

    // Debit sender account
    await client.query(
      `UPDATE accounts SET available = available - $1 WHERE user_email = $2`,
      [amount, sender_email]
    );

    // Credit recipient account
    await client.query(
      `UPDATE accounts SET available = available + $1 WHERE user_email = $2`,
      [amount, recipient_email]
    );

    // Update user balances
    await client.query(
      `UPDATE users SET available_balance = available_balance - $1 WHERE user_email = $2`,
      [amount, sender_email]
    );
    await client.query(
      `UPDATE users SET available_balance = available_balance + $1 WHERE user_email = $2`,
      [amount, recipient_email]
    );

    await client.query('COMMIT');
    return { success: true };
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

/**
 * Make external transfer (wire/ACH/crypto - no balance update yet)
 * @param {object} params - {user_email, recipient_email, bank_name, routing_number, account_number, method, amount, description}
 * @returns {Promise<{id, status}>}
 */
export async function makeExternalTransfer({ user_email, recipient_email, bank_name, routing_number, account_number, method = 'wire', amount, description }) {
  const result = await query(
    `INSERT INTO transfers (user_email, recipient_email, bank_name, routing_number, account_number, method, amount, description, status)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'pending')
     RETURNING id, status`,
    [user_email, recipient_email, bank_name, routing_number, account_number, method, amount, description]
  );
  return result.rows[0];
}

/**
 * Get transfers for a user (sent and received)
 * @param {string} user_email - User email
 * @param {number} limit - Max records
 * @returns {Promise<array>} Array of transfers
 */
export async function getTransfers(user_email, limit = 100) {
  const result = await query(
    `SELECT id, user_email AS sender, recipient_email AS recipient, bank_name, 
            routing_number, account_number, method, amount, description, status, created_at
     FROM transfers
     WHERE user_email = $1 OR recipient_email = $1
     ORDER BY created_at DESC
     LIMIT $2`,
    [user_email, limit]
  );
  return result.rows;
}

// ==============================
// Loans
// ==============================

/**
 * Apply for a loan
 * @param {object} params - {user_email, amount, term_months, apr_estimate, monthly_payment_estimate}
 * @returns {Promise<{id, status}>}
 */
export async function applyLoan({ user_email, amount, term_months, apr_estimate, monthly_payment_estimate }) {
  const result = await query(
    `INSERT INTO loans (user_email, amount, term_months, apr_estimate, monthly_payment_estimate)
     VALUES ($1, $2, $3, $4, $5)
     RETURNING id, status`,
    [user_email, amount, term_months, apr_estimate, monthly_payment_estimate]
  );
  return result.rows[0];
}

/**
 * Approve a loan and credit user account
 * @param {string} loan_id - Loan UUID
 * @returns {Promise<{success}>}
 */
export async function approveLoan(loan_id) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Get loan details
    const loanRes = await client.query(
      `SELECT user_email, amount FROM loans WHERE id = $1`,
      [loan_id]
    );
    if (!loanRes.rows[0]) throw new Error('Loan not found');

    const { user_email, amount } = loanRes.rows[0];

    // Approve and unlock loan
    await client.query(
      `UPDATE loans SET status = 'approved', locked = false WHERE id = $1`,
      [loan_id]
    );

    // Credit user account
    await client.query(
      `UPDATE accounts SET available = available + $1 WHERE user_email = $2`,
      [amount, user_email]
    );

    // Update user balance
    await client.query(
      `UPDATE users SET available_balance = available_balance + $1 WHERE user_email = $2`,
      [amount, user_email]
    );

    await client.query('COMMIT');
    return { success: true };
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

/**
 * Get loans for a user
 * @param {string} user_email - User email
 * @param {number} limit - Max records
 * @returns {Promise<array>} Array of loans
 */
export async function getUserLoans(user_email, limit = 100) {
  const result = await query(
    `SELECT id, amount, term_months, apr_estimate, monthly_payment_estimate, status, fee_paid, locked, created_at
     FROM loans
     WHERE user_email = $1
     ORDER BY created_at DESC
     LIMIT $2`,
    [user_email, limit]
  );
  return result.rows;
}

/**
 * Get single loan by ID
 * @param {string} loan_id - Loan UUID
 * @returns {Promise<object>} Loan details
 */
export async function getLoan(loan_id) {
  const result = await query(
    `SELECT id, user_email, amount, term_months, apr_estimate, monthly_payment_estimate, status, fee_paid, locked, created_at
     FROM loans WHERE id = $1`,
    [loan_id]
  );
  return result.rows[0];
}

/**
 * Mark loan fee as paid and unlock loan
 * @param {string} loan_id - Loan UUID
 * @returns {Promise<{success}>}
 */
export async function payLoanFee(loan_id) {
  const result = await query(
    `UPDATE loans SET fee_paid = true, locked = false WHERE id = $1
     RETURNING fee_paid, locked`,
    [loan_id]
  );
  if (!result.rows[0]) throw new Error('Loan not found');
  return { success: true };
}
