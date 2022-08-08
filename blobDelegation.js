// blobDelegation = require("./blobDelegation")
// blobDelegation.getOauthToken().then(t => blobDelegation.getDelegationKey(t)).then(k => console.log(blobDelegation.getDelegationSas(k)))

const request = require('./request').request
const crypto = require('crypto')
const { v4: uuidv4 } = require('uuid');

const STORAGEACCOUNT = 'ideasyncraticstorstd'
const STORAGECONTAINER = 'receive'
const BLOBHOST = `${STORAGEACCOUNT}.blob.core.windows.net`
const DELEGATOR_SECRET = 'XXXREPLACEMEXXX'
const TENANT = 'cfeeb63b-ccfc-439f-a359-4cdc09697570'
const CLIENT_ID = '28402510-86c3-4d18-b214-75053928456e'

/* implements https://docs.microsoft.com/en-us/rest/api/storageservices/create-user-delegation-sas
## PRE
* create storage account
* create storage container
* create AAD app registration
* role assignment of AAD app to storage container as a "storage blob data contributor"
* role assignment of AAD app to storage account as a "storage blob delegator"

## Get OAuth token with app client secret
https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow

## Get Delegation key with OAuth token
https://docs.microsoft.com/en-us/rest/api/storageservices/create-user-delegation-sas

## Create SAS with delegation key
https://github.com/Azure/azure-sdk-for-js/blob/736de0823c93db08cd03ca4c2b07e45e3b825702/sdk/storage/storage-blob/src/sas/BlobSASSignatureValues.ts#L537
*/

// oauth tokens are short-lived ~1 hour
async function getOauthToken() {
  const body = `client_id=${CLIENT_ID}&scope=https%3A%2F%2Fstorage.azure.com%2F.default&client_secret=${DELEGATOR_SECRET}&grant_type=client_credentials`
  const options = {
    hostname: 'login.microsoftonline.com',
    port: 443,
    path: `/${TENANT}/oauth2/v2.0/token`,
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Content-Length': Buffer.byteLength(body),
      'Accept': '*/*',
      'User-Agent': 'jssas'
    },
    method: 'POST'
  }

  res = await request(options, body)

  try{
    return JSON.parse(res.body).access_token
  } catch(e) {
    return null
  }
}


// create the delegation key to be valid for 2 days, but probably only going to use it to generate SAS for one day 
// as the SAS we generate will be valid for 24 hours or less
async function getDelegationKey(token) {
  const start = new Date()
  const expiry = new Date()
  start.setMinutes(start.getMinutes() - 15)
  expiry.setHours(expiry.getHours() + 48)

  const body = `<?xml version="1.0" encoding="utf-8"?>
    <KeyInfo>
      <Start>${azISODate(start)}</Start>
      <Expiry>${azISODate(expiry)}</Expiry>
    </KeyInfo>`

  const options = {
    hostname: BLOBHOST,
    port: 443,
    path: '/?restype=service&comp=userdelegationkey',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/xml',
      'Accept': 'application/xml',
      'x-ms-version': '2019-12-12',
      'Content-Length': Buffer.byteLength(body),
      'User-Agent': 'jssas'
    },
    method: 'POST'
  }
    
  res = await request(options, body)
  
  const signedOid = res.body.match(/<SignedOid>(.*)<\/SignedOid>/)?.[1]
  const signedTid = res.body.match(/<SignedTid>(.*)<\/SignedTid>/)?.[1]
  const signedStart = res.body.match(/<SignedStart>(.*)<\/SignedStart>/)?.[1]
  const signedExpiry = res.body.match(/<SignedExpiry>(.*)<\/SignedExpiry>/)?.[1]
  const signedVersion = res.body.match(/<SignedVersion>(.*)<\/SignedVersion>/)?.[1]
  const keyValue64 = res.body.match(/<Value>(.*)<\/Value>/)?.[1]

  return { signedOid, signedTid, signedStart, signedExpiry, signedVersion, keyValue64 }
}

// see https://docs.microsoft.com/en-us/rest/api/storageservices/create-user-delegation-sas#construct-a-user-delegation-sas
// for the format for the signature of the fields. But note that the docs are not quite accurate and the
// signature format for the 2019-12-12 API is actually the same as the 2020-02-10 version. In other words
// you need an extra blank line for the `signedSnapshotTime` as seen in the SDK
// https://github.com/Azure/azure-sdk-for-js/blob/736de08/sdk/storage/storage-blob/src/sas/BlobSASSignatureValues.ts#L537
// returns a 12hour-valid sas url and the blob uuid
// set options.blobHost to use a non-default blob host
function getDelegationSas(getDelegationKeyResponse, options={}) {
  const blobUuid = uuidv4()
  const blobPath = `${blobUuid.substring(0,1)}/${blobUuid.substring(0,2)}/${blobUuid}`
  const newCanonicalResource = `/blob/${STORAGEACCOUNT}/${STORAGECONTAINER}/${blobPath}`
  const start = new Date()
  const expiry = new Date()
  start.setMinutes(start.getMinutes() - 15)
  expiry.setHours(expiry.getHours() + 12)

  const params = {
    sp: 'wt',                                      // signedPermissions: write, tag
    st: azISODate(start),                          // signedStart: validity start
    se: azISODate(expiry),                         // signedExpiry: validity end
    canonicalizedResource: newCanonicalResource,   // canonicalizedResource: blob resource identifier
    skoid: getDelegationKeyResponse.signedOid,     // signedObjectId: security principal. From getDelegationKey
    sktid: getDelegationKeyResponse.signedTid,     // signedTenantId: tenant Id. From getDelegationKey
    skt: getDelegationKeyResponse.signedStart,     // signedKeyStartTime: start time of delegation key. From getDelegationKey
    ske: getDelegationKeyResponse.signedExpiry,    // signedKeyExpiryTime: expiration time of delegation key. From getDelegationKey
    sks: 'b',                                      // signedKeyService: blob service
    skv: '2019-12-12',                             // signedKeyVersion: signed key API version. From getDelegationKey
    //saoid: '',                                     // signedAuthorizedObjectId: NA
    //suoid: '',                                     // signedUnauthorizedObjectId: NA
    //scid: '',                                      // signedCorrelationId: log id, unavailable for 2019-12-12
    sip: '',                                       // signedIp: restrict to ip
    spr: 'https',                                  // signedProtocol: restrict to https
    sv: '2019-12-12',                              // signedVersion: storage API version
    sr: 'b',                                       // signedResource: storage resource type. b is blob
    signedSnapshotTime: '',                        // EMPTY see comment at start of method
    rscc: '',                                      // Cache-Control override, unused
    rscd: '',                                      // Content-Disposition override, unused
    rsce: '',                                      // Content-Encoding override, unused
    rscl: '',                                      // Content-Language override, unused
    rsct: ''                                       // Content-Type override, unused
  }
console.log(Object.values(params).join("\n"))
  const sig = crypto
    .createHmac("sha256", Buffer.from(getDelegationKeyResponse.keyValue64, "base64"))
    .update(Object.values(params).join("\n"), "utf8")
    .digest("base64")

  const paramsQueryString = Object.keys(params)
    .filter(k => params[k].length > 0)
    .map(k => `${k}=${encodeURIComponent(params[k])}`)
    .join('&')
 return {
  blobUuid: blobUuid,
  blobUrl: `https://${options.blobHost || BLOBHOST}/${STORAGECONTAINER}/${blobPath}?${paramsQueryString}&sig=${encodeURIComponent(sig)}`
 }
}

// JavaScript ISO dates have 3 millisecond digits. Azure needs 0 or 7.
function azISODate(date) {
  return date.toISOString().replace(/\.[0-9][0-9][0-9]Z/, 'Z')
}

module.exports.getOauthToken = getOauthToken
module.exports.getDelegationKey = getDelegationKey
module.exports.getDelegationSas = getDelegationSas
