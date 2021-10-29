const JWT = require('@hapi/jwt');
const InvariantError = require('../exceptions/InvariantError');

const TokenManager = {
  generateAccessToken: (payload) => JWT.token.generate(payload, process.env.ACCESS_TOKEN_KEY),
  generateRefreshToken(payload) {
    return JWT.token.generate(payload, process.env.REFRESH_TOKEN_KEY);
  },
  verifyRefreshToken(refreshToken) {
    try {
      const artifact = JWT.token.decode(refreshToken);
      JWT.token.verifySignature(artifact, process.env.REFRESH_TOKEN_KEY);
      const { payload } = artifact.decoded;
      return payload;
    } catch (error) {
      throw new InvariantError('Refresh token tidak valid');
    }
  },
};

module.exports = TokenManager;
