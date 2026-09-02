import { checkSpf } from './spf.js';
import { checkDkim } from './dkim.js';
import { checkDmarc } from './dmarc.js';
import { checkBimi } from './bimi.js';
import { checkMx } from './mx.js';
import { checkMtaSts } from './mtasts.js';
import { checkTlsRpt } from './tlsrpt.js';
import { checkDnssec } from './dnssec.js';
import { checkCaa } from './caa.js';
import { checkHeaders } from './headers.js';
import { checkSecurityTxt } from './securitytxt.js';
import { checkTls } from './tls.js';
import { checkTakeover } from './takeover.js';

// Every check is a pure function of (evidence, now). Order here is display order.
export function runChecks(evidence, now = new Date()) {
  return [
    checkSpf(evidence),
    checkDkim(evidence),
    checkDmarc(evidence),
    checkBimi(evidence),
    checkMx(evidence),
    checkMtaSts(evidence),
    checkTlsRpt(evidence),
    checkDnssec(evidence),
    checkCaa(evidence),
    checkTls(evidence),
    checkHeaders(evidence),
    checkSecurityTxt(evidence, now),
    checkTakeover(evidence),
  ];
}

export {
  checkSpf,
  checkDkim,
  checkDmarc,
  checkBimi,
  checkMx,
  checkMtaSts,
  checkTlsRpt,
  checkDnssec,
  checkCaa,
  checkHeaders,
  checkSecurityTxt,
  checkTls,
  checkTakeover,
};
