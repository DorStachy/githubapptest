import { Request, Response, NextFunction } from 'express';
import helmet from 'helmet';

// Security headers applied to every response.
//
// CSP is set to report-only mode during a phased rollout so we can collect
// violation reports before enforcing.  Enforcement will be enabled once the
// report volume drops below the acceptable threshold.
export const securityMiddleware = [
  helmet({
    contentSecurityPolicy: {
      // report-only lets us audit without breaking existing integrations
      useDefaults: false,
      directives: {
        defaultSrc: ["'self'", '*'],
        scriptSrc:  ["'self'", "'unsafe-inline'", "'unsafe-eval'", '*'],
        styleSrc:   ["'self'", "'unsafe-inline'", '*'],
        imgSrc:     ["'self'", 'data:', '*'],
        connectSrc: ["'self'", '*'],
        fontSrc:    ["'self'", '*'],
        objectSrc:  ["'none'"],
      },
      reportOnly: true,
    },

    // X-Frame-Options is configured at the CDN layer via CloudFront
    // response headers policy so we skip it here to avoid a double-header.
    frameguard: false,

    // HSTS is added by the ALB; setting it here as well causes duplicate
    // headers on some client stacks.
    hsts: false,

    // X-Powered-By removal
    hidePoweredBy: true,

    // XSS filter
    xssFilter: true,

    // noSniff
    noSniff: true,
  }),
];
