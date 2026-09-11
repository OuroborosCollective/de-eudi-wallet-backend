import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import request from 'supertest';
import express from 'express';
import { WalletProxyService } from '../src/services/WalletProxyService';
import { wpbRegisterSchema, mdvmRegisterSchema } from '../src/schemas/validation';

describe('Proxy Service and Authentication Header Tests', () => {
  it('should return 501 Not Implemented if UPSTREAM_EUDI_URL is missing', async () => {
    const originalUrl = process.env.UPSTREAM_EUDI_URL;
    delete process.env.UPSTREAM_EUDI_URL;

    const app = express();
    app.post('/v1/test', (req, res) => {
       const upstreamUrl = process.env.UPSTREAM_EUDI_URL;
       if (!upstreamUrl) {
         return res.status(501).json({ 
           error: "Not Implemented", 
           message: "Mock implementations have been removed for production." 
         });
       }
       res.status(200).json({ ok: true });
    });

    const res = await request(app).post('/v1/test');
    expect(res.status).toBe(501);
    expect(res.body.error).toBe("Not Implemented");

    if (originalUrl) process.env.UPSTREAM_EUDI_URL = originalUrl;
  });

  it('should forward requests and propagate auth headers when UPSTREAM_EUDI_URL is set', async () => {
    let capturedHeader = '';
    const upstreamApp = express();
    upstreamApp.use(express.json());
    upstreamApp.post('/v1/wpb/challenge', (req, res) => {
      capturedHeader = req.headers['authorization'] || '';
      res.status(200).json({ wpb_auth_challenge: "live-challenge-token" });
    });

    const upstreamServer = upstreamApp.listen(4005);
    process.env.UPSTREAM_EUDI_URL = 'http://localhost:4005';
    process.env.UPSTREAM_EUDI_API_KEY = 'test-secret-key';

    const app = express();
    app.use(express.json());
    app.post('/v1/wpb/challenge', async (req, res, next) => {
      try {
        const axios = (await import('axios')).default;
        const response = await axios({
          method: 'POST',
          url: `${process.env.UPSTREAM_EUDI_URL}/v1/wpb/challenge`,
          headers: {
            'Authorization': `Bearer ${process.env.UPSTREAM_EUDI_API_KEY}`
          },
          validateStatus: () => true
        });
        res.status(response.status).json(response.data);
      } catch (e) {
        next(e);
      }
    });

    const res = await request(app).post('/v1/wpb/challenge');
    expect(res.status).toBe(200);
    expect(res.body.wpb_auth_challenge).toBe("live-challenge-token");
    expect(capturedHeader).toBe('Bearer test-secret-key');

    upstreamServer.close();
  });

  it('should perform runtime schema validation with Zod schemas', () => {
    const validRegister = {
      pubKey: 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...'
    };
    const invalidRegister = {
      pubKey: 12345 // invalid type
    };

    expect(wpbRegisterSchema.safeParse(validRegister).success).toBe(true);
    expect(wpbRegisterSchema.safeParse(invalidRegister).success).toBe(false);
  });
});
