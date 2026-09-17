import handler from '../../pages/api/auth/reset-password'
import * as dbHelper from '../../lib/db-helper'

jest.mock('../../lib/db-helper')

const createMockReqRes = (method = 'POST', body = {}) => {
  const req = { method, body }
  const res = {
    status: jest.fn().mockReturnThis(),
    json: jest.fn().mockReturnThis(),
  }
  return { req, res }
}

describe('/api/auth/reset-password', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    process.env.PASSWORD_HASH_SECRET = 'test_secret'
  })

  it('rejects non-POST methods with 405', async () => {
    const { req, res } = createMockReqRes('GET')
    await handler(req, res)
    expect(res.status).toHaveBeenCalledWith(405)
  })

  it('rejects missing token with 400', async () => {
    const { req, res } = createMockReqRes('POST', { password: 'validPassword123' })
    await handler(req, res)
    expect(res.status).toHaveBeenCalledWith(400)
    expect(res.json).toHaveBeenCalledWith({ error: 'Reset token is required' })
  })

  it('rejects password shorter than 6 characters with 400', async () => {
    const { req, res } = createMockReqRes('POST', { token: 'valid_tok', password: '123' })
    await handler(req, res)
    expect(res.status).toHaveBeenCalledWith(400)
    expect(res.json).toHaveBeenCalledWith({ error: 'Password must be at least 6 characters long' })
  })

  it('rejects invalid or unknown token with 400', async () => {
    dbHelper.getUserByQuery.mockResolvedValueOnce([])
    const { req, res } = createMockReqRes('POST', { token: 'fake_token', password: 'validPassword123' })

    await handler(req, res)
    expect(res.status).toHaveBeenCalledWith(400)
    expect(res.json).toHaveBeenCalledWith({ error: 'Invalid or expired password reset link' })
  })

  it('invalidates and rejects expired token with 400', async () => {
    const expiredDate = new Date(Date.now() - 1000 * 60).toISOString()
    dbHelper.getUserByQuery.mockResolvedValueOnce([
      { _id: 'user_1', resetToken: 'expired_tok', resetTokenExpires: expiredDate },
    ])
    dbHelper.updateUserByQuery.mockResolvedValueOnce({ ok: 1 })

    const { req, res } = createMockReqRes('POST', { token: 'expired_tok', password: 'validPassword123' })
    await handler(req, res)

    expect(dbHelper.updateUserByQuery).toHaveBeenCalledWith(
      { _id: 'user_1' },
      { resetToken: null, resetTokenExpires: null }
    )
    expect(res.status).toHaveBeenCalledWith(400)
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({ error: expect.stringContaining('expired') })
    )
  })

  it('successfully updates hashed password and clears resetToken with 200', async () => {
    const futureDate = new Date(Date.now() + 1000 * 60 * 60).toISOString()
    dbHelper.getUserByQuery.mockResolvedValueOnce([
      { _id: 'user_1', resetToken: 'valid_tok', resetTokenExpires: futureDate },
    ])
    dbHelper.updateUserByQuery.mockResolvedValueOnce({ ok: 1 })

    const { req, res } = createMockReqRes('POST', { token: 'valid_tok', password: 'newValidPassword123' })
    await handler(req, res)

    expect(dbHelper.updateUserByQuery).toHaveBeenCalledWith(
      { _id: 'user_1' },
      expect.objectContaining({
        password: expect.any(String),
        resetToken: null,
        resetTokenExpires: null,
      })
    )
    expect(res.status).toHaveBeenCalledWith(200)
    expect(res.json).toHaveBeenCalledWith({ message: 'Password has been reset successfully' })
  })

  it('handles database errors with 500', async () => {
    dbHelper.getUserByQuery.mockRejectedValueOnce(new Error('DB Failure'))
    const { req, res } = createMockReqRes('POST', { token: 'tok', password: 'validPassword123' })

    await handler(req, res)
    expect(res.status).toHaveBeenCalledWith(500)
  })
})
