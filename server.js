#!/usr/bin/env node

/**
 * DMVIC Certificate Proxy Server
 *
 * This Node.js service acts as a proxy between Supabase Edge Functions and the DMVIC API
 * to handle client certificate authentication (mTLS) which is not supported in Supabase Edge Functions.
 */

const express = require('express');
const cors = require('cors');
const https = require('https');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;

// CORS configuration
const corsOptions = {
  origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:54321', 'http://127.0.0.1:54321','/*'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key']
};

app.use(cors(corsOptions));
app.use(express.json({ limit: '10mb' }));

// Security middleware - API Key validation
const validateApiKey = (req, res, next) => {
  const apiKey = req.headers['x-api-key'] || req.headers['authorization']?.replace('Bearer ', '');

  // For development, allow requests without API key
  if (process.env.NODE_ENV === 'development') {
    return next();
  }

  if (!apiKey || apiKey !== process.env.PROXY_API_KEY) {
    return res.status(401).json({
      error: 'Unauthorized',
      message: 'Valid API key required'
    });
  }

  next();
};

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'dmvic-certificate-proxy',
    timestamp: new Date().toISOString(),
    version: '1.0.0'
  });
});

// DMVIC Certificate Issuance Proxy Endpoint
app.post('/dmvic/certificate/issue', validateApiKey, async (req, res) => {
  try {
    // Validate required fields
    const requiredFields = ['token', 'clientId', 'certificateRequest'];

    for (const field of requiredFields) {
      if (!req.body[field]) {
        return res.status(400).json({
          error: 'Missing required field',
          field: field
        });
      }
    }

    const { token, clientId, certificateRequest, apimSubscriptionKey } = req.body;

    // Load client certificate
    const certPath = path.join(__dirname, 'certs', 'dmvic-client.p12');

    if (!fs.existsSync(certPath)) {
      console.error('❌ Client certificate file not found:', certPath);
      return res.status(500).json({
        error: 'Server configuration error',
        message: 'Client certificate not configured'
      });
    }

    const certBuffer = fs.readFileSync(certPath);

    // Make the HTTPS request with client certificate
    const result = await makeDMVICRequest({
      url: `${process.env.DMVIC_BASE_URL}/api/V5/IntermediaryIntegration/IssuanceTypeCCertificate`,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': `Bearer ${token}`,
        'Ocp-Apim-Subscription-Key': apimSubscriptionKey,
        'ClientID': clientId,
        'User-Agent': 'FlexySure-DMVIC-Proxy/1.0'
      },
      data: certificateRequest,
      cert: certBuffer,
      passphrase: process.env.DMVIC_CERT_PASSWORD
    });

    // Return the response from DMVIC
    res.status(result.statusCode).json(result.data);

  } catch (error) {
    console.error('❌ Error in DMVIC certificate issuance:', error);

    // Handle different types of errors
    if (error.code === 'ENOTFOUND') {
      return res.status(500).json({
        error: 'Network error',
        message: 'Unable to connect to DMVIC API'
      });
    }

    if (error.response) {
      console.error('🔴 DMVIC API error:', error.response.status, error.response.data);
      return res.status(error.response.status).json({
        error: 'DMVIC API error',
        message: error.response.data || error.message,
        status: error.response.status
      });
    }

    // Generic error
    res.status(500).json({
      error: 'Internal server error',
      message: error.message
    });
  }
});

// Make HTTPS request with client certificate
function makeDMVICRequest({ url, method, headers, data, cert, passphrase }) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);

    const options = {
      hostname: urlObj.hostname,
      port: urlObj.port || 443,
      path: urlObj.pathname + urlObj.search,
      method: method,
      headers: headers,
      // Client certificate configuration
      pfx: cert,
      passphrase: passphrase,
      // SSL options
      rejectUnauthorized: true,
      secureProtocol: 'TLS_method'
    };

    const req = https.request(options, (res) => {
      let responseData = '';

      res.on('data', (chunk) => {
        responseData += chunk;
      });

      res.on('end', () => {
        try {
          const parsedData = responseData ? JSON.parse(responseData) : {};
          resolve({
            statusCode: res.statusCode,
            headers: res.headers,
            data: parsedData
          });
        } catch (parseError) {
          resolve({
            statusCode: res.statusCode,
            headers: res.headers,
            data: { message: responseData }
          });
        }
      });
    });

    req.on('error', (error) => {
      console.error('🔴 HTTPS request error:', error);
      reject(error);
    });

    // Send request data
    if (data && (method === 'POST' || method === 'PUT')) {
      req.write(JSON.stringify(data));
    }

    req.end();
  });
}

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('🔴 Unhandled error:', error);
  res.status(500).json({
    error: 'Internal server error',
    message: error.message
  });
});

// Confirm Certificate Issuance endpoint
app.post('/dmvic/certificate/confirm', async (req, res) => {
  try {
    const { token, clientId, apimSubscriptionKey, confirmationRequest } = req.body;

    // Validate required fields
    if (!token || !clientId || !apimSubscriptionKey || !confirmationRequest) {
      return res.status(400).json({
        error: 'Missing required fields',
        required: ['token', 'clientId', 'apimSubscriptionKey', 'confirmationRequest']
      });
    }

    // Validate confirmation request structure
    const { IssuanceRequestID } = confirmationRequest;
    
    if (!IssuanceRequestID) {
      return res.status(400).json({
        error: 'Missing IssuanceRequestID in confirmationRequest'
      });
    }

    const certPath = path.join(__dirname, 'certs', 'dmvic-client.p12');
    
    if (!fs.existsSync(certPath)) {
      throw new Error('Client certificate not found. Run: node setup-certs.js');
    }

    const certBuffer = fs.readFileSync(certPath);

    // Make the HTTPS request with client certificate
    const result = await makeDMVICRequest({
      url: `${process.env.DMVIC_BASE_URL}/api/v5/Integration/ConfirmCertificateIssuance`,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': `Bearer ${token}`,
        'Ocp-Apim-Subscription-Key': apimSubscriptionKey,
        'ClientID': clientId,
        'User-Agent': 'FlexySure-DMVIC-Proxy/1.0'
      },
      data: confirmationRequest,
      cert: certBuffer,
      passphrase: process.env.DMVIC_CERT_PASSWORD
    });

    // Return the response from DMVIC
    res.status(result.statusCode).json(result.data);

  } catch (error) {
    console.error('❌ Error in DMVIC certificate confirmation:', error);

    // Handle different types of errors
    if (error.code === 'ENOTFOUND') {
      return res.status(500).json({
        error: 'Network error',
        message: 'Unable to connect to DMVIC API'
      });
    }

    if (error.response) {
      console.error('🔴 DMVIC API error:', error.response.status, error.response.data);
      return res.status(error.response.status).json({
        error: 'DMVIC API error',
        message: error.response.data || error.message,
        details: error.response.data
      });
    }

    // Generic error
    res.status(500).json({
      error: 'Certificate confirmation failed',
      message: error.message
    });
  }
});

// Get Certificate endpoint
app.post('/dmvic/certificate/get', async (req, res) => {
  try {
    const { token, clientId, apimSubscriptionKey, certificateNumber } = req.body;

    // Validate required fields
    if (!token || !clientId  || !certificateNumber) {
      return res.status(400).json({
        error: 'Missing required fields',
        required: ['token', 'clientId', 'apimSubscriptionKey', 'certificateNumber']
      });
    }

    const certPath = path.join(__dirname, 'certs', 'dmvic-client.p12');
    
    if (!fs.existsSync(certPath)) {
      throw new Error('Client certificate not found. Run: node setup-certs.js');
    }

    const certBuffer = fs.readFileSync(certPath);

    // Make the HTTPS request with client certificate
    const result = await makeDMVICRequest({
      url: `${process.env.DMVIC_BASE_URL}/api/v5/Integration/GetCertificate`,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': `Bearer ${token}`,
        'Ocp-Apim-Subscription-Key': apimSubscriptionKey,
        'ClientID': clientId,
        'User-Agent': 'FlexySure-DMVIC-Proxy/1.0'
      },
      data: { CertificateNumber: certificateNumber },
      cert: certBuffer,
      passphrase: process.env.DMVIC_CERT_PASSWORD
    });

    // Return the response from DMVIC
    res.status(result.statusCode).json(result.data);

  } catch (error) {
    console.error('❌ Error in DMVIC get certificate:', error);

    // Handle different types of errors
    if (error.code === 'ENOTFOUND') {
      return res.status(500).json({
        error: 'Network error',
        message: 'Unable to connect to DMVIC API'
      });
    }

    if (error.response) {
      console.error('🔴 DMVIC API error:', error.response.status, error.response.data);
      return res.status(error.response.status).json({
        error: 'DMVIC API error',
        message: error.response.data || error.message,
        details: error.response.data
      });
    }

    // Generic error
    res.status(500).json({
      error: 'Get certificate failed',
      message: error.message
    });
  }
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Not found',
    message: `Endpoint ${req.method} ${req.originalUrl} not found`,
    availableEndpoints: [
      'GET /health',
      'POST /dmvic/certificate/issue',
      'POST /dmvic/certificate/confirm',
      'POST /dmvic/certificate/get'
    ]
  });
});

// Start server
app.listen(PORT, () => {
  console.log('🚀 DMVIC Certificate Proxy Server started');
  console.log('🌐 Server running at:', `http://localhost:${PORT}`);
  console.log('🌍 Environment:', process.env.NODE_ENV || 'development');

  // Check if certificate file exists
  const certPath = path.join(__dirname, 'certs', 'dmvic-client.p12');
  if (fs.existsSync(certPath)) {
    console.log('✅ Client certificate found');
  } else {
    console.log('⚠️  Client certificate not found - run: node setup-certs.js');
  }

  console.log('🔧 Ready to proxy DMVIC certificate requests!');
});

// Handle graceful shutdown
process.on('SIGTERM', () => {
  process.exit(0);
});

process.on('SIGINT', () => {
  process.exit(0);
});