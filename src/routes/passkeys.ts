import express from 'express';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import { pool } from '../db';
import { authenticateToken, requireWriteAccess, requireStepUp } from '../middleware/auth';
import { enqueueMail, mailConfig } from '../mail';
import {
  issueTokenForUser,
  markStepUp,
  tokenFingerprint,
} from '../utils/authHelpers';

// マイボード routes/passkeys.ts（step-up 強化後の最終形）の Motion 移植。
// 差分: セッション表の代わりに JWT を使うため、チャレンジのセッション紐付けは
// JWT の指紋（SHA-256）で行い、step-up 状態は users.last_stepup_at で判定する。

const router = express.Router();

const RP_ID = (() => {
  try { return new URL(mailConfig.publicBaseUrl).hostname; } catch { return 'motion.parumenn.com'; }
})();
const EXPECTED_ORIGIN = mailConfig.publicBaseUrl;
const NO_PASSKEYS = 'パスキーが登録されていません';

const b64urlEncode = (buf: Uint8Array) => Buffer.from(buf).toString('base64url');
const b64urlDecode = (s: string) => Buffer.from(s, 'base64url');

type ChallengeKind = 'register' | 'auth' | 'stepup';

async function loadUser(userId: string) {
  const { rows } = await pool.query(
    `SELECT id, email, role, status, password_login_disabled FROM users WHERE id = $1`,
    [userId]
  );
  return rows[0] ?? null;
}

async function saveChallenge(userId: string | null, kind: ChallengeKind, challenge: string, fingerprint: string | null = null) {
  await pool.query(
    `INSERT INTO webauthn_challenges (user_id, challenge, kind, token_fingerprint, expires_at)
     VALUES ($1, $2, $3, $4, now() + interval '10 minutes')`,
    [userId, challenge, kind, fingerprint]
  );
}

// fingerprint を渡した場合は、その JWT で発行されたチャレンジだけを消費する
// （登録系・step-up 系はセッションに紐付ける。ログイン前の auth はセッションが
//   存在しないため従来どおりユーザー紐付けのみとし、fingerprint は渡さない）
async function takeChallenge(userId: string, kind: ChallengeKind, fingerprint?: string): Promise<string | null> {
  const { rows } = fingerprint
    ? await pool.query(
        `SELECT id, challenge FROM webauthn_challenges
          WHERE user_id = $1 AND kind = $2 AND token_fingerprint = $3 AND expires_at > now()
          ORDER BY created_at DESC LIMIT 1`,
        [userId, kind, fingerprint]
      )
    : await pool.query(
        `SELECT id, challenge FROM webauthn_challenges
          WHERE user_id = $1 AND kind = $2 AND expires_at > now()
          ORDER BY created_at DESC LIMIT 1`,
        [userId, kind]
      );
  if (rows.length === 0) return null;
  await pool.query(`DELETE FROM webauthn_challenges WHERE id = $1`, [rows[0].id]);
  return rows[0].challenge;
}

// Framing 対策: 他オリジンに埋め込まれた文脈での WebAuthn 応答を拒否する
function isCrossOrigin(response: any): boolean {
  try {
    const clientData = JSON.parse(Buffer.from(response?.response?.clientDataJSON ?? '', 'base64url').toString('utf8'));
    return clientData.crossOrigin === true;
  } catch {
    return true; // 読めない応答は検証失敗として扱う
  }
}

// Backup Eligible / Backup State の変化検出（マイボードと同一ロジック）。
// 移行前の既存パスキー（保存値 NULL）は今回の値を保存して次回から比較対象にする。
async function assertBackupStateUnchanged(passkey: any, info: { credentialDeviceType: string; credentialBackedUp: boolean }, userId: string): Promise<boolean> {
  const storedType: string | null = passkey.credential_device_type ?? null;
  const storedBackedUp: boolean | null = passkey.backed_up ?? null;
  if (storedType === null || storedBackedUp === null) {
    await pool.query(
      `UPDATE passkeys SET credential_device_type = $1, backed_up = $2 WHERE credential_id = $3 AND user_id = $4`,
      [info.credentialDeviceType, info.credentialBackedUp, passkey.credential_id, userId]
    );
    return true;
  }
  return storedType === info.credentialDeviceType && storedBackedUp === info.credentialBackedUp;
}

const jwtOnly = [authenticateToken, requireWriteAccess];
const jwtStepUp = [authenticateToken, requireWriteAccess, requireStepUp];

// ---- パスキー登録 ----
router.post('/passkeys/register/options', ...jwtStepUp, async (req, res) => {
  try {
    const user = await loadUser((req as any).user.userId);
    if (!user) return res.status(404).json({ error: 'ユーザーが見つかりません' });
    const { rows } = await pool.query(`SELECT credential_id FROM passkeys WHERE user_id = $1`, [user.id]);
    const options = await generateRegistrationOptions({
      rpName: 'Motion',
      rpID: RP_ID,
      userID: new TextEncoder().encode(user.id),
      userName: user.email,
      attestationType: 'none',
      // -257 (RSASSA-PKCS1-v1_5) は非推奨のため外す（マイボードと同一）
      supportedAlgorithmIDs: [-8, -7, -37],
      excludeCredentials: rows.map((r: any) => ({ id: r.credential_id, type: 'public-key' as const })),
      authenticatorSelection: { residentKey: 'required', userVerification: 'preferred' },
    });
    await saveChallenge(user.id, 'register', options.challenge, tokenFingerprint(req));
    return res.json(options);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'サーバーエラーが発生しました' });
  }
});

router.post('/passkeys/register/verify', ...jwtStepUp, async (req, res) => {
  try {
    const user = await loadUser((req as any).user.userId);
    if (!user) return res.status(404).json({ error: 'ユーザーが見つかりません' });
    const response = req.body?.response;
    const name = typeof req.body?.name === 'string' && req.body.name.length >= 1 && req.body.name.length <= 50
      ? req.body.name : user.email;
    if (!response || isCrossOrigin(response)) {
      return res.status(400).json({ error: 'パスキーの検証に失敗しました', code: 'verification_failed' });
    }
    // credid 長チェック（WebAuthn 仕様 §7.1.25: 1023 バイト以下）
    const credIdRaw: string = response?.id ?? '';
    if (!credIdRaw || Buffer.from(credIdRaw, 'base64url').length > 1023) {
      return res.status(400).json({ error: 'パスキーの検証に失敗しました', code: 'verification_failed' });
    }
    const challenge = await takeChallenge(user.id, 'register', tokenFingerprint(req));
    if (!challenge) return res.status(400).json({ error: 'チャレンジの有効期限が切れました。もう一度お試しください', code: 'challenge_expired' });

    let regResult;
    try {
      regResult = await verifyRegistrationResponse({
        response,
        expectedChallenge: challenge,
        expectedOrigin: EXPECTED_ORIGIN,
        expectedRPID: RP_ID,
      });
    } catch {
      return res.status(400).json({ error: 'パスキーの検証に失敗しました', code: 'verification_failed' });
    }
    const { verified, registrationInfo } = regResult;
    if (!verified || !registrationInfo) {
      return res.status(400).json({ error: 'パスキーの検証に失敗しました', code: 'verification_failed' });
    }
    const { credential } = registrationInfo;
    if (Buffer.from(credential.id, 'base64url').length > 1023) {
      return res.status(400).json({ error: 'パスキーの検証に失敗しました', code: 'verification_failed' });
    }
    await pool.query(
      `INSERT INTO passkeys (user_id, credential_id, public_key, name, sign_count, credential_device_type, backed_up)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [user.id, credential.id, b64urlEncode(credential.publicKey), name, credential.counter,
       registrationInfo.credentialDeviceType, registrationInfo.credentialBackedUp]
    );
    await enqueueMail(pool, user.email, 'passkey_added', { name });
    return res.json({ ok: true });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'サーバーエラーが発生しました' });
  }
});

// ---- パスキー一覧 / 削除 ----
router.get('/passkeys', ...jwtOnly, async (req, res) => {
  try {
    const userId = (req as any).user.userId;
    const { rows } = await pool.query(
      `SELECT id, name, created_at, last_used_at FROM passkeys WHERE user_id = $1 ORDER BY created_at DESC`,
      [userId]
    );
    return res.json(rows);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'サーバーエラーが発生しました' });
  }
});

router.delete('/passkeys/:id', ...jwtStepUp, async (req, res) => {
  try {
    const user = await loadUser((req as any).user.userId);
    if (!user) return res.status(404).json({ error: 'ユーザーが見つかりません' });
    const id = req.params.id;
    const { rows } = await pool.query(`SELECT id FROM passkeys WHERE id = $1 AND user_id = $2`, [id, user.id]);
    if (rows.length === 0) return res.status(404).json({ error: 'パスキーが見つかりません' });
    const { rows: cnt } = await pool.query(`SELECT count(*)::int AS count FROM passkeys WHERE user_id = $1`, [user.id]);
    if (user.password_login_disabled && cnt[0].count === 1) {
      return res.status(400).json({ error: 'パスワードログインが無効化されているため、最後のパスキーは削除できません', code: 'last_passkey' });
    }
    await pool.query(`DELETE FROM passkeys WHERE id = $1`, [id]);
    await enqueueMail(pool, user.email, 'passkey_removed', {});
    return res.json({ ok: true });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'サーバーエラーが発生しました' });
  }
});

// ---- パスキーログイン ----
router.post('/passkeys/login/options', async (req, res) => {
  try {
    // 常にユーザーネームレス方式で返す。email を渡しても credential_id や
    // アカウント存在可否を漏らさない（論文 AT: Allow Credentials 対策、マイボードと同一）
    const options = await generateAuthenticationOptions({ rpID: RP_ID, allowCredentials: [] });
    await saveChallenge(null, 'auth', options.challenge);
    return res.json(options);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'サーバーエラーが発生しました' });
  }
});

router.post('/passkeys/login/verify', async (req, res) => {
  try {
    const response = req.body?.response;
    if (!response || isCrossOrigin(response)) {
      return res.status(400).json({ error: 'パスキーの検証に失敗しました', code: 'verification_failed' });
    }
    // ユーザーネームレス: credential_id からユーザーを逆引きする
    const { rows: pkRows } = await pool.query(
      `SELECT p.credential_id, p.public_key, p.sign_count, p.credential_device_type, p.backed_up, p.user_id, u.email, u.role
         FROM passkeys p JOIN users u ON u.id = p.user_id
        WHERE p.credential_id = $1 AND u.email_verified_at IS NOT NULL AND u.status = 'approved'`,
      [response.id]
    );
    if (pkRows.length === 0) return res.status(400).json({ error: NO_PASSKEYS, code: 'no_passkeys' });
    const passkey = pkRows[0];
    const target = { id: passkey.user_id as string, email: passkey.email as string, role: passkey.role as string };

    // userHandle が返ってきた場合はユーザーとの一致を確認する
    const userHandle = response.response?.userHandle;
    if (userHandle) {
      const handleUserId = Buffer.from(userHandle, 'base64url').toString('utf8');
      if (handleUserId !== target.id) return res.status(400).json({ error: NO_PASSKEYS, code: 'no_passkeys' });
    }

    // clientDataJSON に含まれる challenge と一致する無名チャレンジを消費する
    let presentedChallenge: string | null = null;
    try {
      const clientData = JSON.parse(Buffer.from(response.response.clientDataJSON, 'base64url').toString('utf8'));
      presentedChallenge = typeof clientData.challenge === 'string' ? clientData.challenge : null;
    } catch { presentedChallenge = null; }
    if (!presentedChallenge) {
      return res.status(400).json({ error: 'チャレンジの有効期限が切れました。もう一度お試しください', code: 'challenge_expired' });
    }
    const { rows: chRows } = await pool.query(
      `DELETE FROM webauthn_challenges
        WHERE user_id IS NULL AND kind = 'auth' AND challenge = $1 AND expires_at > now()
        RETURNING id`,
      [presentedChallenge]
    );
    if (chRows.length === 0) {
      return res.status(400).json({ error: 'チャレンジの有効期限が切れました。もう一度お試しください', code: 'challenge_expired' });
    }

    let authResult;
    try {
      authResult = await verifyAuthenticationResponse({
        response,
        expectedChallenge: presentedChallenge,
        expectedOrigin: EXPECTED_ORIGIN,
        expectedRPID: RP_ID,
        credential: {
          id: passkey.credential_id,
          publicKey: b64urlDecode(passkey.public_key),
          counter: Number(passkey.sign_count),
        },
      });
    } catch {
      return res.status(400).json({ error: 'パスキーの検証に失敗しました', code: 'verification_failed' });
    }
    const { verified, authenticationInfo } = authResult;
    if (!verified || !authenticationInfo) {
      return res.status(400).json({ error: 'パスキーの検証に失敗しました', code: 'verification_failed' });
    }
    if (!(await assertBackupStateUnchanged(passkey, authenticationInfo, target.id))) {
      return res.status(400).json({ error: 'パスキーの検証に失敗しました', code: 'verification_failed' });
    }
    await pool.query(
      `UPDATE passkeys SET sign_count = $1, last_used_at = now() WHERE credential_id = $2 AND user_id = $3`,
      [authenticationInfo.newCounter, passkey.credential_id, target.id]
    );
    const { token, user } = await issueTokenForUser(target);
    return res.json({ ok: true, token, user });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'サーバーエラーが発生しました' });
  }
});

// ---- step-up 認証（パスキー方式） ----
// パスワード方式は routes/auth.ts の /stepup/password。
router.post('/stepup/passkey/options', ...jwtOnly, async (req, res) => {
  try {
    const user = await loadUser((req as any).user.userId);
    if (!user) return res.status(404).json({ error: 'ユーザーが見つかりません' });
    const { rows } = await pool.query(`SELECT credential_id FROM passkeys WHERE user_id = $1`, [user.id]);
    if (rows.length === 0) return res.status(400).json({ error: NO_PASSKEYS, code: 'no_passkeys' });
    const options = await generateAuthenticationOptions({
      rpID: RP_ID,
      userVerification: 'required',
      allowCredentials: rows.map((r: any) => ({ id: r.credential_id, type: 'public-key' as const })),
    });
    await saveChallenge(user.id, 'stepup', options.challenge, tokenFingerprint(req));
    return res.json(options);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'サーバーエラーが発生しました' });
  }
});

router.post('/stepup/passkey/verify', ...jwtOnly, async (req, res) => {
  try {
    const user = await loadUser((req as any).user.userId);
    if (!user) return res.status(404).json({ error: 'ユーザーが見つかりません' });
    const response = req.body?.response;
    if (!response || isCrossOrigin(response)) {
      return res.status(400).json({ error: 'パスキーの検証に失敗しました', code: 'verification_failed' });
    }
    const { rows: pkRows } = await pool.query(
      `SELECT credential_id, public_key, sign_count, credential_device_type, backed_up FROM passkeys WHERE user_id = $1`,
      [user.id]
    );
    const passkey = pkRows.find((r: any) => r.credential_id === response.id);
    if (!passkey) return res.status(400).json({ error: NO_PASSKEYS, code: 'no_passkeys' });
    const challenge = await takeChallenge(user.id, 'stepup', tokenFingerprint(req));
    if (!challenge) return res.status(400).json({ error: 'チャレンジの有効期限が切れました。もう一度お試しください', code: 'challenge_expired' });

    let authResult;
    try {
      authResult = await verifyAuthenticationResponse({
        response,
        expectedChallenge: challenge,
        expectedOrigin: EXPECTED_ORIGIN,
        expectedRPID: RP_ID,
        credential: {
          id: passkey.credential_id,
          publicKey: b64urlDecode(passkey.public_key),
          counter: Number(passkey.sign_count),
        },
      });
    } catch {
      return res.status(400).json({ error: 'パスキーの検証に失敗しました', code: 'verification_failed' });
    }
    const { verified, authenticationInfo } = authResult;
    if (!verified || !authenticationInfo) {
      return res.status(400).json({ error: 'パスキーの検証に失敗しました', code: 'verification_failed' });
    }
    if (!(await assertBackupStateUnchanged(passkey, authenticationInfo, user.id))) {
      return res.status(400).json({ error: 'パスキーの検証に失敗しました', code: 'verification_failed' });
    }
    await pool.query(
      `UPDATE passkeys SET sign_count = $1, last_used_at = now() WHERE credential_id = $2 AND user_id = $3`,
      [authenticationInfo.newCounter, passkey.credential_id, user.id]
    );
    await markStepUp(user.id);
    return res.json({ ok: true });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'サーバーエラーが発生しました' });
  }
});

// ---- パスワードログイン有効/無効トグル（マイボード /settings/password-login と同一パス） ----
router.post('/settings/password-login', ...jwtStepUp, async (req, res) => {
  try {
    const user = await loadUser((req as any).user.userId);
    if (!user) return res.status(404).json({ error: 'ユーザーが見つかりません' });
    const disabled = req.body?.disabled;
    if (typeof disabled !== 'boolean') return res.status(400).json({ error: 'disabled は真偽値で指定してください' });
    if (disabled) {
      const { rows } = await pool.query(`SELECT count(*)::int AS count FROM passkeys WHERE user_id = $1`, [user.id]);
      if (rows[0].count === 0) return res.status(400).json({ error: NO_PASSKEYS, code: 'no_passkeys' });
    }
    await pool.query(`UPDATE users SET password_login_disabled = $1 WHERE id = $2`, [disabled, user.id]);
    return res.json({ ok: true, password_login_disabled: disabled });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'サーバーエラーが発生しました' });
  }
});

export default router;
