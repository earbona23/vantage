// Known dangling-CNAME takeover fingerprints.
//
// Each entry describes a hosting service a subdomain might CNAME to, and how to
// tell that the target is UNCLAIMED (and therefore claimable by an attacker):
//   cname       — regex matching the CNAME target hostname
//   body        — string that appears in the "not configured / no such site"
//                 page the service serves for an unclaimed name (HTTP 200/404)
//   nxdomain    — true when a CNAME whose target does not resolve at all is,
//                 for this service, itself the takeover signal
//
// This is a fingerprint match, not an exploit: we read the public page the
// service already serves. We never attempt to claim anything.
export const TAKEOVER_FINGERPRINTS = [
  {
    service: 'GitHub Pages',
    cname: /\.github\.io$/i,
    body: "There isn't a GitHub Pages site here",
    nxdomain: false,
  },
  {
    service: 'Heroku',
    cname: /\.herokuapp\.com$/i,
    body: 'No such app',
    nxdomain: true,
  },
  {
    service: 'AWS S3',
    cname: /s3[.-].*amazonaws\.com$/i,
    body: 'NoSuchBucket',
    nxdomain: false,
  },
  {
    service: 'Shopify',
    cname: /\.myshopify\.com$/i,
    body: 'Sorry, this shop is currently unavailable',
    nxdomain: false,
  },
  {
    service: 'Fastly',
    cname: /\.fastly\.net$/i,
    body: 'Fastly error: unknown domain',
    nxdomain: false,
  },
  {
    service: 'Pantheon',
    cname: /\.pantheonsite\.io$/i,
    body: '404 error unknown site',
    nxdomain: false,
  },
  {
    service: 'Tumblr',
    cname: /\.domains\.tumblr\.com$/i,
    body: "Whatever you were looking for doesn't currently exist at this address",
    nxdomain: false,
  },
  {
    service: 'Zendesk',
    cname: /\.zendesk\.com$/i,
    body: 'Help Center Closed',
    nxdomain: false,
  },
  {
    service: 'Surge.sh',
    cname: /\.surge\.sh$/i,
    body: 'project not found',
    nxdomain: false,
  },
  {
    service: 'Bitbucket',
    cname: /\.bitbucket\.io$/i,
    body: 'Repository not found',
    nxdomain: false,
  },
  {
    service: 'Ghost',
    cname: /\.ghost\.io$/i,
    body: 'Domain error',
    nxdomain: false,
  },
  {
    service: 'Unbounce',
    cname: /\.unbounce\.com$/i,
    body: 'The requested URL was not found on this server',
    nxdomain: false,
  },
  {
    service: 'Readme.io',
    cname: /\.readme\.io$/i,
    body: 'Project doesnt exist... yet!',
    nxdomain: false,
  },
  {
    service: 'Azure',
    cname: /\.(azurewebsites\.net|cloudapp\.net|trafficmanager\.net|azureedge\.net)$/i,
    body: null,
    nxdomain: true,
  },
  {
    service: 'AWS Elastic Beanstalk',
    cname: /\.elasticbeanstalk\.com$/i,
    body: null,
    nxdomain: true,
  },
];

// Given a CNAME target and (optionally) a fetched body, decide whether this is
// a dangling/claimable pointer. Returns the matched fingerprint or null.
export function matchTakeover(cnameTarget, body, targetResolves) {
  if (!cnameTarget) return null;
  for (const fp of TAKEOVER_FINGERPRINTS) {
    if (!fp.cname.test(cnameTarget)) continue;
    // Body fingerprint: the service is serving its unclaimed-name page.
    if (fp.body && typeof body === 'string' && body.includes(fp.body)) return fp;
    // NXDOMAIN signal: for these services a CNAME to a non-resolving target
    // is itself claimable.
    if (fp.nxdomain && targetResolves === false) return fp;
  }
  return null;
}
